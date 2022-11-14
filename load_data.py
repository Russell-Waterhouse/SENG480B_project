import pandas as pd


def get_data():
    df2018 = pd.read_json('data/nvdcve-1.1-2018.json')
    df2019 = pd.read_json('data/nvdcve-1.1-2019.json')
    df2020 = pd.read_json('data/nvdcve-1.1-2020.json')
    df2021 = pd.read_json('data/nvdcve-1.1-2021.json')
    frames = [df2018, df2019, df2020, df2021]
    return pd.concat(frames)


def get_2018_data():
    return get_valid_data(pd.read_json('data/nvdcve-1.1-2018.json'))


def get_2019_data():
    return get_valid_data(pd.read_json('data/nvdcve-1.1-2019.json'))


def get_2020_data():
    return get_valid_data(pd.read_json('data/nvdcve-1.1-2020.json'))


def get_2021_data():
    return get_valid_data(pd.read_json('data/nvdcve-1.1-2021.json'))


def get_valid_data(unvalidated_data):
    valid_data = unvalidated_data.copy()
    for i in range(len(unvalidated_data.index)-1, 0, -1):
        item = unvalidated_data.iloc[i]
        d1 = item["CVE_Items"]["impact"]
        if len(d1) < 2:
            valid_data = valid_data.drop(valid_data.index[i])
    return valid_data


if __name__ == '__main__':
    get_2018_data()
