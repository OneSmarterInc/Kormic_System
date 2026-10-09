import os
import pytest
import shutil

@pytest.fixture(scope="session", autouse=True)
def setup_meshkor_db(request):
    if not shutil.which("pg_ctl"):
        pytest.skip("pg_ctl is not installed, skipping.")
        
    # We retrieve the postgresql_proc fixture dynamically
    postgresql_proc = request.getfixturevalue("postgresql_proc")
    
    dsn = f"postgresql://{postgresql_proc.user}@{postgresql_proc.host}:{postgresql_proc.port}/postgres"
    os.environ["MESHKOR_DATABASE_URL"] = dsn
    os.environ["KORMIC_DEPLOYMENT_MODE"] = "development"
    
    import importlib
    import hq_backend.hq_db
    import hq_backend.hq_server
    
    importlib.reload(hq_backend.hq_db)
    importlib.reload(hq_backend.hq_server)
