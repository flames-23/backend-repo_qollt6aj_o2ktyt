from pydantic import BaseModel, Field, EmailStr
from typing import Optional, Dict, List
from datetime import datetime

# Users collection schema
class User(BaseModel):
    name: Optional[str] = Field(None, description="Full name")
    email: EmailStr = Field(..., description="Email address")
    password_hash: Optional[str] = Field(None, description="BCrypt hash of password (null for OAuth-only accounts)")
    provider: str = Field("local", description="Auth provider: local | google")
    picture: Optional[str] = Field(None, description="Avatar URL")
    is_verified: bool = Field(False, description="Email verified")

# Domains collection schema
class Domain(BaseModel):
    owner_id: Optional[str] = Field(None, description="User ID of the owner")
    domain: str = Field(..., description="Custom domain name")
    verification_token: str = Field(..., description="TXT token expected at _verify.<domain>")
    verified: bool = Field(False, description="Whether DNS TXT record is verified")

# Links collection schema
class Link(BaseModel):
    owner_id: Optional[str] = Field(None, description="User ID of link owner (None for guest)")
    original_url: str = Field(..., description="Destination URL")
    code: str = Field(..., description="Short code / alias")
    domain: Optional[str] = Field(None, description="Custom branded domain; null uses default host")
    title: Optional[str] = Field(None, description="Optional title for the link")
    expires_at: Optional[datetime] = Field(None, description="Optional expiration datetime")
    password_hash: Optional[str] = Field(None, description="BCrypt hash if password-protected")
    one_time: bool = Field(False, description="Whether link is one-time open")
    disabled: bool = Field(False, description="Whether link is disabled")
    device_targets: Dict[str, Optional[str]] = Field(default_factory=dict, description="Device-specific target URLs: desktop/mobile/tablet/ios/android")

# Click events collection schema
class Click(BaseModel):
    link_id: str = Field(..., description="Associated link _id as string")
    code: str = Field(..., description="Short code at time of click")
    ip: Optional[str] = Field(None, description="IP address")
    country: Optional[str] = Field(None, description="Country code or name")
    device: Optional[str] = Field(None, description="Device type")
    browser: Optional[str] = Field(None, description="Browser family")
    os: Optional[str] = Field(None, description="Operating system")
    referer: Optional[str] = Field(None, description="Referer header")
