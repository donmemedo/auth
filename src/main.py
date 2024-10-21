import secure
import uvicorn
from src.config import settings
from src.dependencies import validate_token,PermissionsValidator
from src.encoder import encoder,decoder
from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException



app = FastAPI(docs_url="/docs")
# app = FastAPI(openapi_url=None,docs_url="/docs")

csp = secure.ContentSecurityPolicy().default_src("'self'").frame_ancestors("'none'")
hsts = secure.StrictTransportSecurity().max_age(31536000).include_subdomains()
referrer = secure.ReferrerPolicy().no_referrer()
cache_value = secure.CacheControl().no_cache().no_store().max_age(0).must_revalidate()
x_frame_options = secure.XFrameOptions().deny()

secure_headers = secure.Secure(
    csp=csp,
    hsts=hsts,
    referrer=referrer,
    cache=cache_value,
    xfo=x_frame_options,
)

#TODO: Uncomment this
# @app.middleware("http")
# async def set_secure_headers(request, call_next):
#     response = await call_next(request)
#     secure_headers.framework.fastapi(response)
#     return response


app.add_middleware(
    CORSMiddleware,
    # allow_origins=[settings.client_origin_url],
    allow_origins=["*"],
    max_age=86400,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# app.add_middleware(
#     CORSMiddleware,
#     # allow_origins=[settings.client_origin_url],
#     allow_origins=["*"],
#     allow_methods=["GET"],
#     allow_headers=["Authorization", "Content-Type"],
#     max_age=86400,
# )


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request, exc):
    message = str(exc.detail)

    return JSONResponse({"message": message}, status_code=exc.status_code)


@app.get("/api/messages/public")
def public():
    return {"text": "This is a public message."}


@app.get("/api/messages/protected", dependencies=[Depends(validate_token)])
def protected():
    return {"text": "This is a protected message."}


@app.get("/api/login", dependencies=[Depends(decoder)])
def protected():
    return {"text": "This is a protected message."}


# @app.get("/api/messages/admin", dependencies=[Depends(validate_token)])
@app.get("/api/token", dependencies=[Depends(encoder)])
def give_token():
    return {"text": "This is a protected message."}


# @app.get("/api/messages/admin", dependencies=[Depends(validate_token)])
@app.get(
    "/api/messages/admin",
    dependencies=[Depends(PermissionsValidator(["admin:read"]))],
)
def admin():
    return {"text": "This is an admin message."}

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=settings.port,
        reload=settings.reload,
        server_header=False,
    )
