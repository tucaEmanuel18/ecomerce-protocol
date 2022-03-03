import json

if __name__ == '__main__':
    f = open('dummy_card_data.json')
    jsonData = json.load(f)
    print(jsonData)
    for i in jsonData['data']['cards']:
        print(i)

    f.close()