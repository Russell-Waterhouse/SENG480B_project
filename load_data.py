import pandas as pd


def get_data():
    df2018 = pd.read_json('data/nvdcve-1.1-2018.json')
    df2019 = pd.read_json('data/nvdcve-1.1-2019.json')
    df2020 = pd.read_json('data/nvdcve-1.1-2020.json')
    df2021 = pd.read_json('data/nvdcve-1.1-2021.json')
    frames = [df2018, df2019, df2020, df2021]
    return pd.concat(frames)


def get_2018_data():
    return pd.read_json('data/nvdcve-1.1-2018.json')


def get_2019_data():
    return pd.read_json('data/nvdcve-1.1-2019.json')


def get_2020_data():
    return pd.read_json('data/nvdcve-1.1-2020.json')


def get_2021_data():
    return pd.read_json('data/nvdcve-1.1-2021.json')
