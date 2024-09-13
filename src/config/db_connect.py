from sqlmodel import create_engine


def get_url():
    user = 'yadmin'
    password = 'qwerty123'
    server = 'db'
    port = '5432'
    db = 'saniraq-kz'
    return f"postgresql+psycopg://{user}:{password}@{server}:{port}/{db}"


engine = create_engine(get_url())