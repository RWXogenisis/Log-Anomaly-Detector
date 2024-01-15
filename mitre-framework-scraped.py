from bs4 import BeautifulSoup
import requests

def get_data(request: str):
    html_text = requests.get('https://attack.mitre.org/techniques/' + request + '/').text
    soup = BeautifulSoup(html_text, 'lxml')

    print('----------------------------------------Description------------------------------------------------')
    title = soup.find('h1').text.strip()
    print(f'Title : {title}')
    print(f'Code : {request}')    
    desc = soup.find('div', class_='description-body')
    if desc:
        print(f'Description : {desc.text.strip()}')
    else:
        print('Description not found')

    print('----------------------------------------Mitigation------------------------------------------------')
    mitigation = soup.find('table', class_='table table-bordered table-alternate mt-2')
    if mitigation:
        for row in mitigation.tbody.find_all('tr'):
            columns = row.find_all('td')

            if columns:
                id = columns[0].text.strip()
                name = columns[1].text.strip()
                desc = columns[2].text.strip()

                print(f'''
                    id : {id}
                    name : {name}
                    description : {desc}''')
    else:
        print('Mitigation table not found')

    print('----------------------------------------Detection------------------------------------------------')
    detection = soup.find('table', class_='table datasources-table table-bordered')
    if detection:
        for row in detection.tbody.find_all('tr'):
            column = row.find_all('td')

            if column:
                id = column[0].text.strip()
                dsource = column[1].text.strip()
                dcomp = column[2].text.strip()
                detects = column[3].text.strip()
                print(f'''
                    id : {id}
                    dsource : {dsource}
                    dcomp : {dcomp}
                    detects : {detects}''')
    else:
        main_div = soup.find('h2', id='detection')
        data = main_div.find_next_sibling('div').text
        print(data.strip())

    print('----------------------------------------Rest------------------------------------------------')
    if len(soup.find_all('div', class_='card-body')) > 1:
        subtechniques = soup.find_all('div', class_='card-body')[0]
        subtable = subtechniques.find('table', class_='table table-bordered')
        if subtable:
            for row in subtable.tbody.find_all('tr'):
                column = row.find_all('td')
                if column:
                    id = column[0].text.strip()
                    name = column[1].text.strip()
                    print(f'''
                        id : {id}
                        name : {name}''')

            tactic_section = soup.find_all('div', class_='card-body')[1].find_all('div', class_='col-md-11 pl-0')[2]
            if 'Tactics:' in tactic_section.text.strip():
                tactic = tactic_section.text.strip().split('Tactics:')[1].replace(" ", "").strip()
                tactic = tactic.replace(",",", ")
            else:
                tactic = tactic_section.text.strip().split('Tactic:')[1]
            print(f'Tactic : {tactic}')
        else:
            print('Subtechniques table not found')
    else:
        tactic_section = soup.find_all('div', class_='card-body')[0].find_all('div', class_='col-md-11 pl-0')[2]
        if 'Tactics:' in tactic_section.text.strip():
            tactic = tactic_section.text.strip().split('Tactics:')[1].replace(" ", "").strip()
            tactic = tactic.replace(",",", ")
        else:
            tactic = tactic_section.text.strip().split('Tactic:')[1]
        print(f'Tactic : {tactic}')

# Debug with specific cases
listt=['T1592',
'T1595',
'T1589',
'T1590',
'T1591',
'T1598',
'T1597',
'T1596',
'T1593',
'T1594',
'T1650',
'T1583',
'T1586',
'T1584',
'T1587',
'T1585',
'T1588',
'T1608',
'T1659',
'T1189',
'T1190',
'T1133',
'T1200',
'T1566',
'T1091',
'T1195',
'T1199',
'T1078',
'T1651',
'T1059',
'T1609',
'T1203',
'T1559',
'T1106',
'T1053',
'T1648',
'T1129',
'T1072',
'T1569',
'T1204',
'T1047',
'T1610',
'T1098',
'T1197',
'T1547',
'T1037',
'T1176',
'T1554',
'T1136',
'T1543',
'T1546',
'T1133',
'T1574',
'T1525',
'T1556',
'T1137',
'T1653',
'T1542',
'T1053',
'T1505',
'T1205',
'T1078',
'T1548',
'T1134',
'T1098',
'T1547',
'T1037',
'T1543',
'T1484',
'T1611',
'T1546',
'T1068',
'T1574',
'T1055',
'T1053',
'T1078',
'T1548',
'T1134',
'T1197',
'T1612',
'T1622',
'T1140',
'T1610',
'T1006',
'T1484',
'T1480',
'T1211',
'T1222',
'T1564',
'T1574',
'T1562',
'T1656',
'T1070',
'T1202',
'T1036',
'T1556',
'T1578',
'T1112',
'T1601',
'T1599',
'T1027',
'T1647',
'T1542',
'T1055',
'T1620',
'T1207',
'T1014',
'T1553',
'T1218',
'T1216',
'T1221',
'T1205',
'T1127',
'T1535',
'T1550',
'T1078',
'T1497',
'T1600',
'T1220',
'T1557',
'T1110',
'T1555',
'T1212',
'T1187',
'T1606',
'T1056',
'T1556',
'T1111',
'T1621',
'T1040',
'T1003',
'T1528',
'T1649',
'T1558',
'T1539',
'T1552',
'T1087',
'T1010',
'T1217',
'T1580',
'T1538',
'T1526',
'T1619',
'T1613',
'T1622',
'T1652',
'T1482',
'T1083',
'T1615',
'T1654',
'T1046',
'T1135',
'T1040',
'T1201',
'T1120',
'T1069',
'T1057',
'T1012',
'T1018',
'T1518',
'T1082',
'T1614',
'T1016',
'T1049',
'T1033',
'T1007',
'T1124',
'T1497',
'T1210',
'T1534',
'T1570',
'T1563',
'T1021',
'T1091',
'T1072',
'T1080',
'T1550',
'T1557',
'T1560',
'T1123',
'T1119',
'T1185',
'T1115',
'T1530',
'T1602',
'T1213',
'T1005',
'T1039',
'T1025',
'T1074',
'T1114',
'T1056',
'T1113',
'T1125',
'T1071',
'T1092',
'T1659',
'T1132',
'T1001',
'T1568',
'T1573',
'T1008',
'T1105',
'T1104',
'T1095',
'T1571',
'T1572',
'T1090',
'T1219',
'T1205',
'T1102',
'T1020',
'T1030',
'T1048',
'T1041',
'T1011',
'T1052',
'T1567',
'T1029',
'T1537',
'T1531',
'T1485',
'T1486',
'T1565',
'T1491',
'T1561',
'T1499',
'T1657',
'T1495',
'T1490',
'T1498',
'T1496',
'T1489',
'T1529',
]

for code in listt:
    get_data(code)

