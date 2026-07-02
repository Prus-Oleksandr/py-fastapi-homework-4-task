from datetime import date, datetime
import re

from fastapi import APIRouter, Depends, status, HTTPException, UploadFile, Form, File
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from config import get_jwt_auth_manager
from config.dependencies import get_s3_storage_client
from database import get_db
from database.models.accounts import UserProfileModel, GenderEnum, UserModel
from schemas.profiles import ProfileResponseSchema
from security.http import get_token
from security.interfaces import JWTAuthManagerInterface
from storages.interfaces import S3StorageInterface

router = APIRouter()


def _decode_token(token: str, jwt_manager: JWTAuthManagerInterface) -> int:
    try:
        token_data = jwt_manager.decode_access_token(token)
        return token_data.get("user_id")
    except Exception as e:
        error_msg = str(e)
        if "expired" in error_msg.lower() or "expire" in error_msg.lower():
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has expired.",
            )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired credentials.",
        )


async def _get_active_user(user_id: int, db: AsyncSession) -> UserModel:
    stmt = select(UserModel).where(UserModel.id == user_id)
    result = await db.execute(stmt)
    user = result.scalars().first()
    if not user or not getattr(user, "is_active", False):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or not active.",
        )
    return user


def _validate_names_and_info(first_name: str, last_name: str, info: str):
    if not info or not info.strip():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Info field cannot be empty or contain only spaces.",
        )
    if not re.match(r"^[a-zA-Z]+$", first_name):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"{first_name} contains non-english letters",
        )
    if not re.match(r"^[a-zA-Z]+$", last_name):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"{last_name} contains non-english letters",
        )


def _validate_birth_and_gender(date_of_birth: str, gender: str):
    try:
        parsed_date = datetime.strptime(date_of_birth, "%Y-%m-%d").date()
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Invalid birth date format. Expected YYYY-MM-DD.",
        )

    if parsed_date.year <= 1900:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Invalid birth date - year must be greater than 1900.",
        )

    today = date.today()
    age = (
        today.year
        - parsed_date.year
        - ((today.month, today.day) < (parsed_date.month, parsed_date.day))
    )
    if age < 18:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="You must be at least 18 years old to register.",
        )

    if gender not in ["man", "woman"]:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Gender must be one of the allowed options.",
        )
    return parsed_date, GenderEnum(gender)


async def _validate_and_read_avatar(avatar: UploadFile) -> bytes:
    if avatar.content_type not in ["image/jpeg", "image/png", "image/jpg"]:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Invalid image format",
        )

    try:
        file_data = await avatar.read()
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Failed to read upload file.",
        )

    if len(file_data) > 1 * 1024 * 1024:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Image size exceeds 1 MB",
        )
    return file_data


@router.post(
    "/users/{user_id}/profile/",
    response_model=ProfileResponseSchema,
    status_code=status.HTTP_201_CREATED,
    summary="Create User Profile",
)
async def create_profile(
    user_id: int,
    first_name: str = Form(...),
    last_name: str = Form(...),
    gender: str = Form(...),
    date_of_birth: str = Form(...),
    info: str = Form(...),
    avatar: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    token: str = Depends(get_token),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    storage: S3StorageInterface = Depends(get_s3_storage_client),
):
    token_user_id = _decode_token(token, jwt_manager)
    current_user = await _get_active_user(token_user_id, db)

    if token_user_id != user_id:
        await _get_active_user(user_id, db)

    is_admin = getattr(current_user, "group_id", 1) == 3
    if token_user_id != user_id and not is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You don't have permission to edit this profile.",
        )

    _validate_names_and_info(first_name, last_name, info)
    parsed_birth_date, db_gender = _validate_birth_and_gender(date_of_birth, gender)
    file_data = await _validate_and_read_avatar(avatar)

    stmt_profile_exists = select(UserProfileModel).where(
        UserProfileModel.user_id == user_id
    )
    result_profile_exists = await db.execute(stmt_profile_exists)
    if result_profile_exists.scalars().first():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User already has a profile.",
        )

    unique_file_name = f"avatars/{user_id}_avatar.jpg"
    try:
        await storage.upload_file(file_name=unique_file_name, file_data=file_data)
        avatar_url = await storage.get_file_url(unique_file_name)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to upload avatar. Please try again later.",
        )

    try:
        new_profile = UserProfileModel(
            user_id=user_id,
            first_name=first_name.lower(),
            last_name=last_name.lower(),
            gender=db_gender,
            date_of_birth=parsed_birth_date,
            info=info,
            avatar=unique_file_name,
        )
        db.add(new_profile)
        await db.commit()
        await db.refresh(new_profile)
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database saving error.",
        )

    return {
        "id": new_profile.id,
        "user_id": new_profile.user_id,
        "first_name": new_profile.first_name,
        "last_name": new_profile.last_name,
        "gender": gender,
        "date_of_birth": date_of_birth,
        "info": new_profile.info,
        "avatar": avatar_url,
    }
