import pandas as pd


def get_data():
    df2018 = pd.read_json('data/nvdcve-1.1-2018.json')
    df2019 = pd.read_json('data/nvdcve-1.1-2019.json')
    df2020 = pd.read_json('data/nvdcve-1.1-2020.json')
    df2021 = pd.read_json('data/nvdcve-1.1-2021.json')
    frames = [df2018, df2019, df2020, df2021]
    return pd.concat(frames)
    # return df2018