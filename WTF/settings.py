
from pathlib import Path
import os
ENVIRONMENT = 'TEST' #PROD|TEST

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent



# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/4.1/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'django-insecure-8thwdmmun8kxq)pv3h3mzpq64^56+ap2m6du^%9@_zn25$^lna'

# SECURITY WARNING: don't run with debug turned on in production!
if ENVIRONMENT == 'TEST':
    DEBUG = True
else:
    DEBUG = False

ALLOWED_HOSTS = ['*']


# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'app',
    'background_task',
    'UserAccounts',
    #'TaskAppConfig',  # Ensure the correct AppConfig is used
    #'app.apps.AppConfig',  # Ensure the custom AppConfig is used
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'WTF.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(BASE_DIR, 'app/templates'), os.path.join(BASE_DIR, '_Log_FW_'), os.path.join(BASE_DIR, 'static') ],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'WTF.wsgi.application'


# Database
# https://docs.djangoproject.com/en/4.1/ref/settings/#databases

# DATABASES = {
#     'default': {
#         'ENGINE': 'django.db.backends.sqlite3',
#         'NAME': BASE_DIR / 'db.sqlite3',
#     }
# }
import os
django_env = os.getenv('DJANGO_ENV', 'local')

DATABASES = {
   'default': {
       'ENGINE': 'django.db.backends.postgresql',
       #'NAME': 'ASA_Check_v3',
       'NAME': 'ASA_Check' if django_env == 'local' else 'ASA_Check_v3',
       #'NAME': 'WhatchThisFirewall' if django_env == 'local' else 'ASA_Check_v3',
       'USER': 'postgres',
       'PASSWORD': 'postgres',
       'HOST': '127.0.0.1' if django_env == 'local' else 'db_postgres',
       'PORT': '5432',
       # ----- Following settings are for Dockerized DB -----
       #'HOST': 'db_postgres',
   }
}



# Password validation
# https://docs.djangoproject.com/en/4.1/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',},
]

# Session handling
# The timeout in seconds before the user is automatically logged out
SESSION_COOKIE_AGE = 60*30  # 30 minutes

# If True, Django will save the session to the database on every request (extending the session duration)
SESSION_SAVE_EVERY_REQUEST = True

# Whether the session cookie should be marked as secure (only sent over HTTPS)
SESSION_COOKIE_SECURE = False  # Set to True if using HTTPS

# The age of the session cookie. After this time the cookie expires and the user is logged out
SESSION_EXPIRE_AT_BROWSER_CLOSE = True  # Optional, logs out user when they close their browser

### SETTINGS FOR BACKGROUND TASKS --------------------------------------
MAX_RUN_TIME = 5*3600                   # background process max task run time
##BACKGROUND_TASK_RUN_ASYNC = False       # True for parallel processing
##BACKGROUND_TASK_ASYNC_THREADS = 2       # Number of parallel tasks
### --------------------------------------------------------------------

# Internationalization
# https://docs.djangoproject.com/en/4.1/topics/i18n/

LANGUAGE_CODE = 'en-us'

#TIME_ZONE = 'UTC'
TIME_ZONE = 'Europe/Rome'

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/4.1/howto/static-files/

STATIC_URL = 'static/'
#STATIC_URL = os.path.join(BASE_DIR, 'staticfiles/')
# STATIC_ROOT is the directory where Django will collect all static files after running 
# python manage.py collectstatic
# This directory should not overlap with any of the directories in STATICFILES_DIRS
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles/')
#STATICFILES_DIRS = [ BASE_DIR / "static", '/var/www/static/',]
STATICFILES_DIRS = [ BASE_DIR / "static", BASE_DIR / "_Log_FW_"]

#MEDIA_URL = 'img/'
#MEDIA_ROOT = os.path.join(BASE_DIR, 'static/img')

#STATICFILES_DIRS = [os.path.join(BASE_DIR, 'app')]

# Default primary key field type
# https://docs.djangoproject.com/en/4.1/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

if ENVIRONMENT == 'TEST':
    LOGGING = {
        'version': 1,
        'disable_existing_loggers': False,
        'formatters': {
            'verbose': {
                'format': '{levelname} {asctime} {module} {message}',
                'style': '{',
            },
            'simple': {
                'format': '{levelname} {message}',
                'style': '{',
            },
        },
        'handlers': {
            'file': {
                #'level': 'DEBUG',
                'level': 'INFO',
                'class': 'logging.FileHandler',
                'filename': os.path.join(BASE_DIR, 'debug.log'),
                'formatter': 'verbose',
            },
            'console': {
                'class': 'logging.StreamHandler',
                'formatter': 'simple',
            },
        },
        'loggers': {
            '': {
                'handlers': ['file', 'console'],
                #'level': 'DEBUG',
                'level': 'INFO',
                'propagate': True,
            },
            'django': {
                'handlers': ['file', 'console'],
                #'level': 'DEBUG',
                'level': 'INFO',
                'propagate': True,
            },
        },
    }


