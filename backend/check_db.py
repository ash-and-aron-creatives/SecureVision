from sqlalchemy import inspect

from backend.database import engine


if __name__ == "__main__":
    print("Tables found in database:", inspect(engine).get_table_names())
