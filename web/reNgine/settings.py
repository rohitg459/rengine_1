import os
from reNgine.init import first_run
from celery.schedules import crontab


# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
#       RENGINE CONFIGURATIONS
# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

RENGINE_HOME = "/usr/src/app"
SECRET_FILE = os.path.join(RENGINE_HOME, "secret")
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

SECRET_KEY = first_run(SECRET_FILE, BASE_DIR)

DEBUG = int(os.environ.get("DEBUG", default=0))

ALLOWED_HOSTS = ["*"]

# Application definition

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "django.contrib.humanize",
    "rest_framework",
    "rest_framework_datatables",
    "dashboard.apps.DashboardConfig",
    "targetApp.apps.TargetappConfig",
    "scanEngine.apps.ScanengineConfig",
    "startScan.apps.StartscanConfig",
    "recon_note.apps.ReconNoteConfig",
    "django_ace",
    "django_celery_beat",
    "mathfilters",
    "drf_yasg",
    "corsheaders",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "login_required.middleware.LoginRequiredMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "corsheaders.middleware.CorsMiddleware",
    "reNgine.middleware.PrintRequestMiddleware",
]


ROOT_URLCONF = "reNgine.urls"


TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [(os.path.join(BASE_DIR, "templates"))],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "reNgine.wsgi.application"

CORS_ORIGIN_ALLOW_ALL = True
CORS_ALLOWED_ORIGINS = ["*"]
CORS_ALLOW_HEADERS = [
    "accept",
    "accept-encoding",
    "authorization",
    "content-type",
    "dnt",
    "origin",
    "user-agent",
    "x-csrftoken",
    "x-requested-with",
]

CORS_ALLOW_CREDENTIALS = True

ALLOWED_HOSTS = ["*"]
CSRF_TRUSTED_ORIGINS = [
    "*",  # for network (Development)
]
# REST Framework

REST_FRAMEWORK = {
    "DEFAULT_RENDERER_CLASSES": (
        "rest_framework.renderers.JSONRenderer",
        "rest_framework.renderers.BrowsableAPIRenderer",
        "rest_framework_datatables.renderers.DatatablesRenderer",
    ),
    "DEFAULT_FILTER_BACKENDS": (
        "rest_framework_datatables.filters.DatatablesFilterBackend",
    ),
    "DEFAULT_PAGINATION_CLASS": "rest_framework_datatables.pagination.DatatablesPageNumberPagination",
    "PAGE_SIZE": 50,
}

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": os.environ.get("POSTGRES_DB"),
        "USER": os.environ.get("POSTGRES_USER"),
        "PASSWORD": os.environ.get("POSTGRES_PASSWORD"),
        "HOST": os.environ.get("POSTGRES_HOST"),
        "PORT": os.environ.get("POSTGRES_PORT"),
        # 'OPTIONS':{
        #     'sslmode':'verify-full',
        #     'sslrootcert': os.path.join(BASE_DIR, 'ca-certificate.crt')
        # }
    }
}

# Password validation
# https://docs.djangoproject.com/en/2.2/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation."
        + "UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation." + "MinimumLengthValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation." + "CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation." + "NumericPasswordValidator",
    },
]


# Internationalization
# https://docs.djangoproject.com/en/2.2/topics/i18n/

LANGUAGE_CODE = "en-us"

TIME_ZONE = "UTC"

USE_I18N = True

USE_L10N = True

USE_TZ = True

MEDIA_ROOT = os.path.join(BASE_DIR, "/usr/src/scan_results")
MEDIA_URL = "/media/"
FILE_UPLOAD_MAX_MEMORY_SIZE = 100000000
FILE_UPLOAD_PERMISSIONS = 0o644

STATIC_URL = "/staticfiles/"
STATIC_ROOT = os.path.join(BASE_DIR, "staticfiles")

STATICFILES_DIRS = [
    os.path.join(BASE_DIR, "static"),
]

LOGIN_REQUIRED_IGNORE_VIEW_NAMES = [
    "login",
]

LOGIN_URL = "login"
LOGIN_REDIRECT_URL = "dashboardIndex"
LOGOUT_REDIRECT_URL = "login"

# Tool Location
TOOL_LOCATION = "/usr/src/app/tools/"

"""
CELERY settings
"""
CELERY_BROKER_URL = os.environ.get("CELERY_BROKER", "redis://redis:6379/0")
CELERY_RESULT_BACKEND = os.environ.get("CELERY_BROKER", "redis://redis:6379/0")
CELERY_ENABLE_UTC = False
CELERY_TIMEZONE = "UTC"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
