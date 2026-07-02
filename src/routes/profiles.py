from datetime import date
import uuid
from fastapi import APIRouter, Depends, status, HTTPException, UploadFile, Form, File
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from database import get_db

from database.models.accounts import UserProfileModel, GenderEnum

from security.http import get_token

from schemas.profiles import (
    ProfileValidationSchema,
    ProfileAvatarValidationSchema,
    ProfileResponseSchema,
)
from security.interfaces import JWTAuthManagerInterface
from storages.s3 import S3StorageClient

router = APIRouter()


def get_s3_storage(
    settings: BaseAppSettings = Depends(get_settings),
) -> S3StorageClient:
    return S3StorageClient(
        endpoint_url=settings.S3_ENDPOINT_URL,
        access_key=settings.S3_ACCESS_KEY,
        secret_key=settings.S3_SECRET_KEY,
        bucket_name=settings.S3_BUCKET_NAME,
    )


@router.post(
    "/{user_id}/",
    response_model=ProfileResponseSchema,
    status_code=status.HTTP_201_CREATED,
    summary="Create User Profile",
    description="Creates a profile for a specific user. Only the account owner can create their profile.",
)
async def create_profile(
    user_id: int,
    first_name: str = Form(...),
    last_name: str = Form(...),
    gender: str = Form(...),
    date_of_birth: date = Form(...),
    info: str = Form(...),
    avatar: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    token: str = Depends(get_token),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    s3_storage: S3StorageClient = Depends(get_s3_storage),
) -> UserProfileModel:

    try:
        token_data = jwt_manager.decode_access_token(token)
        token_user_id = token_data.get("user_id")
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired credentials.",
        )

    if token_user_id != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have permission to create a profile for this user.",
        )

    try:
        ProfileValidationSchema(
            first_name=first_name,
            last_name=last_name,
            gender=gender,
            date_of_birth=date_of_birth,
            info=info,
        )
        ProfileAvatarValidationSchema(avatar=avatar)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e),
        )

    try:
        db_gender = GenderEnum(gender)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid gender option. Mapped options: {[g.value for g in GenderEnum]}",
        )

    stmt = select(UserProfileModel).where(UserProfileModel.user_id == user_id)
    result = await db.execute(stmt)
    if result.scalars().first():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Profile already exists for this user.",
        )

    file_data = await avatar.read()
    file_extension = avatar.filename.split(".")[-1] if avatar.filename else "jpg"
    unique_file_name = f"avatar_{user_id}_{uuid.uuid4().hex}.{file_extension}"

    try:
        await s3_storage.upload_file(file_name=unique_file_name, file_data=file_data)
        avatar_url = await s3_storage.get_file_url(unique_file_name)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to upload avatar to storage: {str(e)}",
        )

    try:
        new_profile = UserProfileModel(
            user_id=user_id,
            first_name=first_name,
            last_name=last_name,
            gender=db_gender,
            date_of_birth=date_of_birth,
            info=info,
            avatar=avatar_url,
        )
        db.add(new_profile)
        await db.commit()
        await db.refresh(new_profile)
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while saving the profile to the database.",
        )
    return new_profile
