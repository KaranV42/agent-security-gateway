import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from asg.idp import idp

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def get_current_principal(token: str = Depends(oauth2_scheme)) -> str:
    """
    Verifies the JWT using the IdP's public key.
    Enforces strict claims validation (iss, aud, exp).
    """
    try:
        public_key_pem = idp.get_public_key_pem()
        
        # Verify signature, expiration, issuer, and audience
        payload = jwt.decode(
            token,
            public_key_pem,
            algorithms=["RS256"],
            issuer="https://idp.asg-prototype.local",
            audience="https://api.asg-prototype.local"
        )
        
        principal_id = payload.get("sub")
        if not principal_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token payload: missing 'sub' claim"
            )
        return principal_id
        
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired"
        )
    except jwt.InvalidIssuerError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token issuer"
        )
    except jwt.InvalidAudienceError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token audience"
        )
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or malformed token"
        )