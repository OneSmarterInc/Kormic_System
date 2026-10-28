import os
import shutil
import pytest

# Set before test collection; never read the checkout's .env in tests.
os.environ["KORMIC_DEPLOYMENT_MODE"] = "development"
os.environ["MESHKOR_DATABASE_URL"] = "postgresql://localhost/unused_test_placeholder"


@pytest.fixture(scope="session")
def setup_meshkor_db(request):
    if not shutil.which("pg_ctl"):
        pytest.skip("PostgreSQL test requires pg_ctl")
    process = request.getfixturevalue("postgresql_proc")
    dsn = f"postgresql://{process.user}@{process.host}:{process.port}/postgres"
    from hq_backend import hq_db
    old = hq_db.DB_URL
    os.environ["MESHKOR_DATABASE_URL"] = dsn
    hq_db.DB_URL = dsn
    yield
    hq_db.DB_URL = old
