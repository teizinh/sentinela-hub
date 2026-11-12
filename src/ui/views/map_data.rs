//! Offline world cartography and country centroid dataset for Sentinela Hub.
//! Provides simplified continental outlines and country centroid lookups in equirectangular coordinates (lat, lon).

/// Simplified continental outline for North America (mainland).
pub static NORTH_AMERICA: &[(f32, f32)] = &[
    (71.0, -156.0), // Pt Barrow, Alaska
    (65.0, -168.0), // Bering Strait
    (60.0, -166.0),
    (55.0, -163.0), // Alaska Peninsula
    (58.0, -152.0), // Kodiak
    (60.0, -145.0), // Gulf of Alaska
    (54.0, -133.0), // Queen Charlotte Islands
    (49.0, -125.0), // Vancouver
    (42.0, -124.5), // Oregon / N. California
    (34.0, -120.0), // Los Angeles
    (32.5, -117.0), // San Diego
    (23.0, -110.0), // Baja tip
    (24.5, -110.5),
    (31.0, -114.5), // Gulf of California head
    (28.0, -112.0),
    (20.0, -105.0), // Mexico Pacific (Puerto Vallarta)
    (16.0, -97.0),  // Oaxaca
    (14.5, -92.0),  // Guatemala
    (9.0, -84.0),   // Costa Rica
    (7.5, -80.0),   // Panama S
    (8.5, -77.5),   // Darien Gap (border with Colombia)
    (9.5, -79.5),   // Panama Caribbean
    (15.5, -83.5),  // Honduras / Cape Gracias a Dios
    (21.0, -87.0),  // Yucatan (Cancun)
    (19.0, -91.0),  // Campeche
    (22.0, -97.5),  // Tampico
    (26.0, -97.0),  // Brownsville
    (29.5, -94.5),  // Houston
    (29.0, -89.5),  // Mississippi Delta
    (30.0, -84.0),  // Florida Panhandle
    (25.0, -80.5),  // Miami / Florida tip
    (28.5, -80.5),  // Cape Canaveral
    (32.0, -81.0),  // Savannah
    (35.5, -75.5),  // Cape Hatteras
    (40.5, -74.0),  // New York Harbor
    (42.5, -70.5),  // Cape Cod / Boston
    (44.5, -66.0),  // Bay of Fundy
    (44.0, -64.0),  // Nova Scotia
    (46.0, -60.0),  // Cape Breton
    (48.0, -64.0),  // Gaspe
    (51.0, -56.0),  // Belle Isle / Newfoundland
    (58.0, -62.5),  // Labrador coast
    (62.0, -66.0),  // Hudson Strait
    (58.0, -80.0),  // Hudson Bay East
    (52.0, -81.0),  // James Bay
    (56.0, -88.0),  // Hudson Bay West
    (63.0, -90.0),  // Hudson Bay North
    (68.0, -85.0),  // Foxe Basin
    (74.0, -95.0),  // Arctic Archipelago
    (71.0, -120.0), // Amundsen Gulf
    (69.5, -137.0), // Mackenzie Delta
    (71.0, -156.0), // Return to Pt Barrow
];

/// Simplified continental outline for Greenland.
pub static GREENLAND: &[(f32, f32)] = &[
    (60.0, -44.0), // Cape Farewell
    (65.0, -40.0), // SE Greenland
    (72.0, -22.0), // E Greenland
    (81.0, -18.0), // NE tip
    (83.0, -32.0), // Morris Jesup (North tip)
    (82.0, -50.0), // NW Greenland
    (76.0, -68.0), // Thule
    (70.0, -54.0), // Disko Bay
    (64.0, -52.0), // Nuuk
    (60.0, -44.0),
];

/// Simplified continental outline for South America.
pub static SOUTH_AMERICA: &[(f32, f32)] = &[
    (8.5, -77.5),   // Panama/Colombia border
    (12.5, -71.5),  // Guajira Peninsula (northernmost)
    (10.5, -64.0),  // Venezuela coast
    (10.5, -61.5),  // Paria Peninsula
    (8.5, -60.0),   // Orinoco Delta
    (5.0, -52.0),   // French Guiana
    (1.0, -50.0),   // Amazon Delta
    (-2.5, -44.0),  // Sao Luis
    (-5.0, -35.5),  // Cape Sao Roque (NE bulge)
    (-8.0, -35.0),  // Recife
    (-13.0, -38.5), // Salvador da Bahia
    (-20.0, -40.0), // Vitoria
    (-23.0, -43.0), // Rio de Janeiro
    (-25.5, -48.5), // Paranagua
    (-30.0, -50.0), // Porto Alegre
    (-34.5, -53.5), // Uruguay coast
    (-35.0, -57.0), // Rio de la Plata
    (-38.0, -57.5), // Mar del Plata
    (-41.0, -63.0), // Golfo San Matias
    (-46.0, -66.0), // Golfo San Jorge
    (-52.0, -68.5), // Strait of Magellan E
    (-55.0, -66.5), // Tierra del Fuego / Cape Horn
    (-54.0, -73.0), // Strait of Magellan W
    (-50.0, -75.0), // Chilean fjords
    (-43.0, -74.0), // Chiloe
    (-37.0, -73.5), // Concepcion
    (-33.0, -71.5), // Valparaiso / Santiago
    (-23.5, -70.5), // Antofagasta
    (-18.5, -70.5), // Arica
    (-14.0, -76.5), // Paracas / Peru
    (-8.0, -79.0),  // Trujillo
    (-5.0, -81.0),  // Punta Parinas (westernmost SA)
    (-1.0, -80.5),  // Guayaquil / Ecuador
    (1.5, -79.0),   // N Ecuador
    (4.0, -77.5),   // Buenaventura / Colombia Pacific
    (7.0, -77.5),   // Gulf of Uraba
    (8.5, -77.5),   // Return to border
];

/// Simplified continental outline for Europe (mainland).
pub static EUROPE: &[(f32, f32)] = &[
    (36.0, -5.5),  // Tarifa / Gibraltar
    (37.0, -8.9),  // Sagres / Algarve
    (38.8, -9.5),  // Cabo da Roca (westernmost mainland Europe)
    (42.0, -8.9),  // Northern Portugal / Minho
    (43.5, -9.3),  // Finisterre / Galicia
    (43.5, -5.5),  // Asturias
    (43.4, -1.8),  // Basque / Bay of Biscay
    (46.0, -1.2),  // La Rochelle
    (48.0, -4.5),  // Brest / Brittany
    (49.5, -1.5),  // Cherbourg / Normandy
    (51.0, 1.8),   // Calais
    (52.0, 4.0),   // Rotterdam / Netherlands
    (53.5, 7.5),   // German Bight
    (55.5, 8.5),   // Jutland West
    (57.5, 10.0),  // Skagen (Denmark tip)
    (55.5, 12.5),  // Copenhagen / Oresund
    (56.0, 13.0),  // Sweden South (Malmo)
    (59.0, 18.0),  // Stockholm
    (65.0, 22.0),  // Gulf of Bothnia top (Lulea)
    (64.0, 25.0),  // Oulu / Finland
    (60.0, 25.0),  // Helsinki
    (60.0, 30.0),  // St Petersburg
    (65.0, 35.0),  // White Sea
    (69.0, 33.0),  // Murmansk / Kola
    (71.0, 28.0),  // North Cape / Norway
    (68.0, 15.0),  // Lofoten
    (63.5, 9.0),   // Trondheim
    (60.5, 5.0),   // Bergen
    (58.0, 7.0),   // Kristiansand
    (59.0, 10.5),  // Oslo
    (54.0, 19.0),  // Gdansk / Poland
    (57.0, 24.0),  // Riga / Baltics
    (59.5, 26.0),  // Tallinn
    (54.0, 28.0),  // Belarus
    (50.0, 36.0),  // Kharkiv / Ukraine East
    (46.5, 38.0),  // Sea of Azov
    (45.0, 35.0),  // Crimea
    (46.5, 30.5),  // Odessa
    (44.0, 28.5),  // Romania Black Sea
    (42.5, 27.5),  // Bulgaria Black Sea
    (41.0, 29.0),  // Bosporus / Istanbul
    (40.0, 24.0),  // Greece Aegean
    (38.0, 24.0),  // Athens
    (36.5, 22.5),  // Peloponnese South
    (39.5, 20.0),  // Ionian coast
    (42.0, 19.0),  // Montenegro / Albania
    (44.5, 15.0),  // Croatia / Dalmatia
    (45.5, 13.5),  // Trieste
    (45.0, 12.3),  // Venice
    (42.0, 15.0),  // Gargano / Adriatic Italy
    (40.5, 18.0),  // Brindisi (heel)
    (38.0, 15.5),  // Reggio Calabria (toe)
    (40.0, 15.5),  // Gulf of Taranto
    (41.0, 14.0),  // Naples
    (42.0, 12.0),  // Rome
    (44.0, 9.8),   // La Spezia / Genoa
    (43.5, 7.0),   // Nice / French Riviera
    (43.3, 5.3),   // Marseille
    (42.5, 3.0),   // Pyrenees / Perpignan
    (41.4, 2.2),   // Barcelona
    (39.5, -0.3),  // Valencia
    (37.5, -1.0),  // Cartagena
    (36.7, -4.4),  // Malaga
    (36.0, -5.5),  // Return to Gibraltar
];

/// Simplified outline for Great Britain.
pub static UNITED_KINGDOM: &[(f32, f32)] = &[
    (50.0, -5.7), // Land's End
    (50.5, -2.5), // Portland
    (50.7, -0.7), // Isle of Wight
    (51.1, 1.4),  // Dover
    (51.8, 1.3),  // Harwich
    (53.0, 0.3),  // The Wash
    (54.0, -0.2), // Flamborough Head
    (55.5, -1.5), // Northumberland
    (57.5, -1.8), // Aberdeen / Peterhead
    (58.6, -3.0), // Duncansby Head (NE tip)
    (58.5, -5.0), // Cape Wrath (NW tip)
    (56.5, -6.0), // Mull / Argyll
    (55.0, -5.0), // Galloway
    (54.0, -3.0), // Morecambe Bay
    (53.3, -4.5), // Anglesey / Wales
    (51.7, -5.3), // St David's Head
    (51.5, -3.0), // Cardiff / Bristol Channel
    (50.3, -4.5), // Plymouth
    (50.0, -5.7), // Return to Land's End
];

/// Simplified outline for Ireland.
pub static IRELAND: &[(f32, f32)] = &[
    (51.4, -9.5),  // Mizen Head (SW tip)
    (51.8, -8.0),  // Cork
    (52.2, -6.3),  // Rosslare
    (53.3, -6.0),  // Dublin
    (54.0, -6.0),  // Dundalk
    (55.2, -6.0),  // Fair Head (NE tip)
    (55.4, -7.3),  // Malin Head (N tip)
    (54.5, -8.5),  // Donegal Bay
    (54.0, -10.0), // Erris Head / Belmullet
    (53.0, -9.5),  // Galway Bay / Cliffs of Moher
    (52.0, -10.5), // Dingle / Kerry
    (51.4, -9.5),  // Return to Mizen Head
];

/// Simplified continental outline for Africa.
pub static AFRICA: &[(f32, f32)] = &[
    (35.8, -5.8),  // Tangier / Ceuta
    (35.5, -2.0),  // Melilla
    (36.0, 1.0),   // Mostaganem / Algeria
    (37.0, 10.0),  // Cape Blanc / Tunis (northernmost)
    (34.0, 10.5),  // Gabes
    (32.8, 13.2),  // Tripoli / Libya
    (31.2, 16.5),  // Sirte
    (32.1, 20.0),  // Benghazi
    (32.5, 23.0),  // Tobruk
    (31.3, 27.2),  // Mersa Matruh / Egypt
    (31.2, 29.9),  // Alexandria
    (31.2, 32.3),  // Port Said / Suez
    (29.9, 32.5),  // Suez City
    (27.8, 34.3),  // Sinai tip (Ras Muhammad)
    (24.0, 35.5),  // Egypt Red Sea
    (19.6, 37.2),  // Port Sudan
    (15.6, 39.5),  // Massawa / Eritrea
    (12.6, 43.1),  // Bab-el-Mandeb
    (11.6, 43.1),  // Djibouti
    (11.8, 51.2),  // Cape Guardafui (Horn of Africa tip)
    (10.4, 51.2),  // Ras Hafun (easternmost Africa)
    (5.3, 48.5),   // Somalia Central
    (2.0, 45.3),   // Mogadishu
    (-0.5, 42.8),  // Kismayo
    (-4.0, 39.7),  // Mombasa / Kenya
    (-6.8, 39.3),  // Dar es Salaam / Tanzania
    (-10.5, 40.5), // Cabo Delgado / Mozambique border
    (-15.0, 40.5), // Mozambique Island
    (-19.8, 34.8), // Beira
    (-26.0, 32.6), // Maputo
    (-28.5, 32.4), // Richards Bay
    (-30.0, 31.0), // Durban
    (-33.0, 28.0), // East London
    (-34.0, 25.6), // Port Elizabeth
    (-34.8, 20.0), // Cape Agulhas (southernmost tip)
    (-34.4, 18.5), // Cape of Good Hope / Cape Town
    (-32.0, 18.2), // Lambert's Bay
    (-28.6, 16.5), // Orange River mouth (Namibia border)
    (-26.6, 15.1), // Luderitz
    (-22.9, 14.5), // Walvis Bay
    (-17.2, 11.8), // Kunene River (Angola border)
    (-12.5, 13.4), // Benguela
    (-8.8, 13.2),  // Luanda
    (-6.0, 12.3),  // Congo River mouth
    (-4.8, 12.0),  // Pointe-Noire
    (-0.5, 9.3),   // Port-Gentil / Gabon
    (2.0, 9.8),    // Equatorial Guinea
    (4.0, 9.2),    // Douala / Cameroon
    (4.5, 7.0),    // Niger Delta / Port Harcourt
    (6.4, 3.4),    // Lagos / Nigeria
    (6.1, 1.2),    // Lome / Togo
    (5.6, -0.2),   // Accra / Ghana
    (4.8, -2.5),   // Cape Three Points
    (5.3, -4.0),   // Abidjan / Ivory Coast
    (4.4, -7.5),   // Cape Palmas / Liberia
    (6.3, -10.8),  // Monrovia
    (8.5, -13.3),  // Freetown / Sierra Leone
    (9.5, -13.7),  // Conakry / Guinea
    (11.8, -15.6), // Bissau
    (13.5, -16.8), // Banjul / The Gambia
    (14.7, -17.5), // Dakar / Senegal (westernmost mainland Africa)
    (16.0, -16.5), // Saint-Louis
    (20.8, -17.0), // Nouadhibou / Mauritania
    (23.7, -16.0), // Dakhla / Western Sahara
    (27.1, -13.2), // Laayoune
    (30.4, -9.6),  // Agadir / Morocco
    (31.5, -9.8),  // Essaouira
    (33.6, -7.6),  // Casablanca
    (34.0, -6.8),  // Rabat
    (35.8, -5.8),  // Return to Tangier
];

/// Simplified outline for Madagascar.
pub static MADAGASCAR: &[(f32, f32)] = &[
    (-12.0, 49.3), // Antsiranana (N tip)
    (-15.5, 50.5), // Masoala Peninsula
    (-18.2, 49.4), // Toamasina
    (-25.0, 47.0), // Tolagnaro (SE tip)
    (-25.6, 45.2), // Cape Sainte Marie (S tip)
    (-23.4, 43.7), // Toliara
    (-16.0, 44.5), // Mahajanga
    (-13.3, 48.2), // Nosy Be
    (-12.0, 49.3), // Return to N tip
];

/// Simplified continental outline for Asia.
pub static ASIA: &[(f32, f32)] = &[
    (41.0, 29.0),   // Bosporus / Istanbul
    (42.0, 35.0),   // Sinop / Turkey Black Sea
    (41.5, 41.5),   // Batumi / Georgia
    (43.5, 40.0),   // Caucasus NW
    (47.0, 47.0),   // Volga Delta / Astrakhan
    (53.0, 50.0),   // Samara
    (60.0, 60.0),   // Ural Mountains Central
    (67.0, 66.0),   // Salekhard / Arctic Urals
    (73.0, 72.0),   // Yamal Peninsula
    (73.0, 80.0),   // Gulf of Ob
    (76.0, 95.0),   // Taymyr Peninsula NW
    (77.7, 104.3),  // Cape Chelyuskin (northernmost mainland Eurasia)
    (74.0, 115.0),  // Khatanga Gulf
    (72.0, 130.0),  // Lena Delta
    (71.0, 150.0),  // Indigirka
    (70.0, 162.0),  // Kolyma
    (67.0, 175.0),  // Chukotka North
    (66.1, 169.8),  // Cape Dezhnev / Bering Strait
    (64.5, 173.0),  // Gulf of Anadyr
    (60.0, 166.0),  // Koryak coast
    (56.5, 163.0),  // Kamchatka East (Ust-Kamchatsk)
    (51.0, 156.8),  // Cape Lopatka (Kamchatka tip)
    (57.0, 156.5),  // Kamchatka West
    (59.5, 143.0),  // Magadan / Okhotsk
    (53.5, 141.0),  // Amur River mouth / Nikolayevsk
    (46.0, 138.0),  // Primorsky Krai
    (43.0, 132.0),  // Vladivostok
    (42.0, 130.5),  // North Korea NE
    (38.0, 128.5),  // East Sea / Sea of Japan
    (35.1, 129.0),  // Busan / South Korea SE
    (34.5, 126.5),  // Mokpo / South Korea SW
    (37.5, 126.5),  // Incheon / Seoul
    (39.0, 125.0),  // Pyongyang / Yellow Sea
    (40.0, 124.0),  // Yalu River / Dandong
    (39.0, 121.5),  // Dalian / Liaodong Peninsula
    (40.5, 122.0),  // Yingkou
    (39.0, 118.0),  // Bohai Bay / Tianjin
    (37.5, 121.5),  // Shandong Peninsula (Weihai)
    (36.0, 120.3),  // Qingdao
    (34.5, 119.5),  // Lianyungang
    (31.5, 121.5),  // Yangtze River mouth / Shanghai
    (30.0, 122.0),  // Zhoushan / Ningbo
    (26.0, 119.5),  // Fuzhou
    (24.5, 118.0),  // Xiamen
    (23.4, 116.8),  // Shantou
    (22.3, 114.2),  // Hong Kong / Pearl River Delta
    (21.5, 111.0),  // Zhanjiang / Leizhou
    (21.5, 108.0),  // Beibu Gulf / Guangxi
    (20.8, 106.7),  // Haiphong / Vietnam
    (16.0, 108.2),  // Da Nang
    (12.0, 109.2),  // Cam Ranh
    (8.6, 104.8),   // Cape Ca Mau (Mekong Delta tip)
    (10.0, 103.0),  // Gulf of Thailand / Kampot
    (13.0, 101.0),  // Rayong
    (13.5, 100.5),  // Bangkok
    (10.0, 99.2),   // Surat Thani
    (6.0, 102.2),   // Kota Bharu / Malaysia East
    (1.3, 103.8),   // Singapore / Johor
    (3.0, 101.4),   // Port Klang / Kuala Lumpur
    (5.4, 100.3),   // Penang
    (7.0, 99.5),    // Satun / Thailand West
    (9.8, 98.6),    // Ranong
    (14.0, 98.2),   // Dawei / Myanmar
    (16.8, 96.2),   // Yangon / Irrawaddy Delta
    (16.0, 94.3),   // Cape Negrais
    (20.0, 92.8),   // Sittwe / Rakhine
    (22.3, 91.8),   // Chittagong / Bangladesh
    (21.8, 89.5),   // Ganges Delta / Sundarbans
    (21.5, 87.0),   // Odisha coast
    (17.7, 83.3),   // Visakhapatnam
    (13.1, 80.3),   // Chennai
    (9.5, 79.0),    // Palk Strait
    (8.1, 77.5),    // Kanyakumari (Cape Comorin, India tip)
    (10.0, 76.2),   // Kochi / Kerala
    (12.9, 74.8),   // Mangalore
    (15.5, 73.8),   // Goa
    (19.0, 72.8),   // Mumbai
    (21.0, 72.7),   // Surat / Gulf of Khambhat
    (21.0, 69.5),   // Kathiawar / Porbandar
    (23.0, 68.5),   // Gulf of Kutch
    (24.8, 67.0),   // Karachi / Pakistan
    (25.3, 62.3),   // Gwadar / Balochistan
    (25.3, 57.0),   // Strait of Hormuz (Iran side)
    (27.0, 56.0),   // Bandar Abbas
    (29.0, 50.8),   // Bushehr / Persian Gulf
    (30.0, 48.5),   // Shatt al-Arab / Basra
    (29.3, 48.0),   // Kuwait City
    (26.0, 50.5),   // Dammam / Bahrain
    (25.3, 51.5),   // Qatar Peninsula
    (24.5, 54.4),   // Abu Dhabi / UAE
    (25.3, 55.3),   // Dubai
    (26.2, 56.3),   // Musandam Peninsula (Oman)
    (23.6, 58.5),   // Muscat
    (22.5, 59.8),   // Ras al Hadd (easternmost Arabia)
    (17.0, 54.1),   // Salalah
    (14.5, 49.1),   // Mukalla / Yemen
    (12.8, 45.0),   // Aden / Gulf of Aden
    (12.6, 43.4),   // Perim / Bab-el-Mandeb (Arabia side)
    (14.8, 42.9),   // Al Hudaydah
    (16.9, 42.5),   // Jizan / Saudi Red Sea
    (21.5, 39.2),   // Jeddah
    (24.0, 38.0),   // Yanbu
    (28.0, 35.0),   // Tabuk / Gulf of Aqaba
    (29.5, 35.0),   // Aqaba
    (31.5, 34.5),   // Gaza / Levant
    (32.8, 35.0),   // Haifa
    (33.9, 35.5),   // Beirut / Lebanon
    (34.8, 35.9),   // Tartus / Syria
    (36.0, 35.9),   // Latakia
    (36.7, 34.6),   // Mersin / Turkey South
    (36.9, 30.7),   // Antalya
    (37.0, 27.4),   // Bodrum / Aegean Turkey
    (38.4, 27.1),   // Izmir
    (40.0, 26.2),   // Dardanelles / Canakkale
    (41.0, 29.0),   // Return to Istanbul
];

/// Simplified outline for Japan (main islands).
pub static JAPAN: &[(f32, f32)] = &[
    (31.2, 130.6), // Kagoshima / Kyushu S
    (33.2, 130.0), // Nagasaki
    (33.9, 131.0), // Shimonoseki / Kanmon
    (34.7, 135.5), // Osaka / Kobe
    (35.3, 139.7), // Tokyo Bay / Yokohama
    (37.0, 141.0), // Fukushima coast
    (41.5, 142.0), // Shimokita Peninsula (Honshu N)
    (42.0, 143.2), // Hokkaido S (Cape Erimo)
    (43.3, 145.8), // Cape Nosappu (Hokkaido E)
    (45.5, 141.9), // Cape Soya (Hokkaido N tip)
    (43.2, 140.5), // Shakotan Peninsula
    (41.8, 140.7), // Hakodate
    (40.7, 140.0), // Tsugaru Peninsula
    (37.9, 139.0), // Niigata
    (37.3, 136.9), // Noto Peninsula
    (35.5, 133.0), // Matsue
    (34.0, 131.0), // Yamaguchi
    (32.8, 131.6), // Miyazaki
    (31.2, 130.6), // Return to Kyushu S
];

/// Simplified continental outline for Australia.
pub static AUSTRALIA: &[(f32, f32)] = &[
    (-10.7, 142.5), // Cape York (northernmost tip)
    (-14.0, 144.0), // Princess Charlotte Bay
    (-17.0, 145.8), // Cairns
    (-19.3, 146.8), // Townsville
    (-23.4, 150.5), // Rockhampton
    (-27.5, 153.0), // Brisbane
    (-28.2, 153.5), // Gold Coast / Point Danger (easternmost)
    (-32.9, 151.8), // Newcastle
    (-33.9, 151.2), // Sydney
    (-37.5, 149.9), // Cape Howe (SE corner)
    (-38.8, 146.4), // Wilsons Promontory (southernmost mainland)
    (-38.3, 144.9), // Melbourne / Port Phillip
    (-38.4, 142.5), // Warrnambool
    (-37.8, 140.8), // Mount Gambier
    (-35.6, 138.1), // Adelaide / Gulf St Vincent
    (-34.7, 135.9), // Port Lincoln / Eyre Peninsula
    (-32.2, 132.5), // Ceduna / Great Australian Bight
    (-31.7, 128.9), // Eucla / WA border
    (-33.9, 121.9), // Esperance
    (-35.0, 117.9), // Albany
    (-34.4, 115.1), // Cape Leeuwin (SW tip)
    (-32.0, 115.8), // Perth / Fremantle
    (-28.8, 114.6), // Geraldton
    (-26.1, 113.2), // Shark Bay / Steep Point (westernmost mainland)
    (-21.8, 114.1), // North West Cape / Exmouth
    (-20.3, 118.6), // Port Hedland
    (-18.0, 122.2), // Broome
    (-16.4, 123.0), // King Sound
    (-14.0, 126.0), // Kimberley / Cape Londonderry
    (-14.8, 128.2), // Cambridge Gulf / Wyndham
    (-12.5, 130.8), // Darwin
    (-11.2, 132.1), // Cobourg Peninsula
    (-12.0, 136.8), // Gove Peninsula / Arnhem Land
    (-14.0, 135.8), // Gulf of Carpentaria West
    (-17.5, 139.5), // Karumba / Gulf of Carpentaria South
    (-14.5, 141.6), // Gulf of Carpentaria East
    (-10.7, 142.5), // Return to Cape York
];

/// Simplified outline for New Zealand.
pub static NEW_ZEALAND: &[(f32, f32)] = &[
    (-34.4, 172.7), // Cape Reinga (North tip)
    (-36.8, 174.8), // Auckland
    (-37.7, 176.2), // Tauranga / Bay of Plenty
    (-37.7, 178.6), // East Cape
    (-39.5, 177.0), // Hawke's Bay / Napier
    (-41.3, 174.8), // Wellington / Cook Strait
    (-41.8, 174.2), // Marlborough / Blenheim
    (-43.5, 172.7), // Christchurch / Banks Peninsula
    (-45.9, 170.5), // Dunedin
    (-46.6, 168.3), // Invercargill / Bluff (South tip)
    (-45.5, 166.6), // Fiordland / West Coast
    (-42.4, 171.2), // Greymouth
    (-40.5, 172.7), // Farewell Spit
    (-40.9, 175.0), // Kapiti coast
    (-39.0, 174.0), // New Plymouth / Mt Taranaki
    (-37.8, 174.8), // Raglan
    (-35.2, 173.3), // Bay of Islands West
    (-34.4, 172.7), // Return to Cape Reinga
];

/// Returns simplified world continental polygon outlines in equirectangular coordinates (lat, lon).
///
/// Includes:
/// - North America (mainland + Greenland)
/// - South America
/// - Europe (mainland + United Kingdom + Ireland)
/// - Africa (mainland + Madagascar)
/// - Asia (mainland + Japan)
/// - Australia / Oceania (Australia mainland + New Zealand)
pub fn get_continent_outlines() -> Vec<&'static [(f32, f32)]> {
    vec![
        NORTH_AMERICA,
        GREENLAND,
        SOUTH_AMERICA,
        EUROPE,
        UNITED_KINGDOM,
        IRELAND,
        AFRICA,
        MADAGASCAR,
        ASIA,
        JAPAN,
        AUSTRALIA,
        NEW_ZEALAND,
    ]
}

/// Offline centroid lookup table mapping country names/codes (case-insensitive) to (latitude, longitude).
///
/// Supports Portuguese and English names, as well as ISO alpha-2 and alpha-3 codes.
/// Defaults to `(39.5, -8.0)` (Portugal) if unknown, empty, or a local/LAN address.
pub fn get_country_centroid(country_or_code: &str) -> (f32, f32) {
    let normalized = country_or_code.trim().to_lowercase();

    match normalized.as_str() {
        // Portugal & Autonomous Regions
        "portugal" | "pt" | "prt" => (39.5, -8.0),

        // Germany / Alemanha
        "alemanha" | "germany" | "deutschland" | "de" | "deu" => (51.16, 10.45),

        // United States / Estados Unidos
        "estados unidos" | "united states" | "united states of america" | "eua" | "us" | "usa" => {
            (37.09, -95.71)
        }

        // China
        "china" | "cn" | "chn" => (35.86, 104.19),

        // France / França
        "frança" | "franca" | "france" | "fr" | "fra" => (46.22, 2.21),

        // Russia / Rússia
        "rússia" | "russia" | "ru" | "rus" => (61.52, 105.31),

        // United Kingdom / Reino Unido
        "reino unido" | "united kingdom" | "great britain" | "uk" | "gb" | "gbr" => {
            (55.37, -3.43)
        }

        // Spain / Espanha
        "espanha" | "spain" | "españa" | "espana" | "es" | "esp" => (40.46, -3.75),

        // Brazil / Brasil
        "brasil" | "brazil" | "br" | "bra" => (-14.23, -51.92),

        // Japan / Japão
        "japão" | "japao" | "japan" | "jp" | "jpn" => (36.20, 138.25),

        // Canada / Canadá
        "canadá" | "canada" | "ca" | "can" => (56.13, -106.34),

        // Netherlands / Holanda / Países Baixos
        "holanda" | "países baixos" | "paises baixos" | "netherlands" | "nl" | "nld" => {
            (52.13, 5.29)
        }

        // Italy / Itália
        "itália" | "italia" | "italy" | "it" | "ita" => (41.87, 12.56),

        // India / Índia
        "índia" | "india" | "in" | "ind" => (20.59, 78.96),

        // Australia / Austrália
        "austrália" | "australia" | "au" | "aus" => (-25.27, 133.77),

        // South Korea / Coreia do Sul
        "coreia do sul" | "coreia" | "south korea" | "korea" | "kr" | "kor" => {
            (35.90, 127.76)
        }

        // Ukraine / Ucrânia
        "ucrânia" | "ucrania" | "ukraine" | "ua" | "ukr" => (48.37, 31.16),

        // Poland / Polónia / Polônia
        "polónia" | "polonia" | "polônia" | "poland" | "pl" | "pol" => (51.91, 19.14),

        // Romania / Roménia / Romênia
        "roménia" | "romenia" | "romênia" | "romania" | "ro" | "rou" => (45.94, 24.96),

        // Vietnam / Vietname / Vietnã
        "vietname" | "vietnam" | "vietnã" | "vietna" | "vn" | "vnm" => (14.05, 108.27),

        // Singapore / Singapura
        "singapura" | "singapore" | "sg" | "sgp" => (1.35, 103.81),

        // Taiwan
        "taiwan" | "tw" | "twn" => (23.69, 120.96),

        // Hong Kong
        "hong kong" | "hongkong" | "hk" | "hkg" => (22.31, 114.16),

        // Sweden / Suécia
        "suécia" | "suecia" | "sweden" | "se" | "swe" => (60.12, 18.64),

        // Switzerland / Suíça
        "suíça" | "suica" | "switzerland" | "ch" | "che" => (46.81, 8.22),

        // Turkey / Turquia
        "turquia" | "turkey" | "türkiye" | "turkiye" | "tr" | "tur" => (38.96, 35.24),

        // Iran / Irão / Irã
        "irão" | "irao" | "irã" | "ira" | "iran" | "ir" | "irn" => (32.42, 53.68),

        // Israel
        "israel" | "il" | "isr" => (31.04, 34.85),

        // Ireland / Irlanda
        "irlanda" | "ireland" | "ie" | "irl" => (53.14, -7.69),

        // Belgium / Bélgica
        "bélgica" | "belgica" | "belgium" | "be" | "bel" => (50.50, 4.46),

        // Austria / Áustria
        "áustria" | "austria" | "at" | "aut" => (47.51, 14.55),

        // Norway / Noruega
        "noruega" | "norway" | "no" | "nor" => (60.47, 8.46),

        // Finland / Finlândia
        "finlândia" | "finlandia" | "finland" | "fi" | "fin" => (61.92, 25.74),

        // Denmark / Dinamarca
        "dinamarca" | "denmark" | "dk" | "dnk" => (56.26, 9.50),

        // Czech Republic / Chéquia / República Checa
        "chéquia" | "chequia" | "república checa" | "republica checa" | "czech republic"
        | "czechia" | "cz" | "cze" => (49.81, 15.47),

        // Bulgaria / Bulgária
        "bulgária" | "bulgaria" | "bg" | "bgr" => (42.73, 25.48),

        // Greece / Grécia
        "grécia" | "grecia" | "greece" | "gr" | "grc" => (39.07, 21.82),

        // South Africa / África do Sul
        "áfrica do sul" | "africa do sul" | "south africa" | "za" | "zaf" => (-30.55, 22.93),

        // Egypt / Egito
        "egito" | "egypt" | "eg" | "egy" => (26.82, 30.80),

        // Mexico / México
        "méxico" | "mexico" | "mx" | "mex" => (23.63, -102.55),

        // Argentina
        "argentina" | "ar" | "arg" => (-38.41, -63.61),

        // Chile
        "chile" | "cl" | "chl" => (-35.67, -71.54),

        // Colombia / Colômbia
        "colômbia" | "colombia" | "co" | "col" => (4.57, -74.29),

        // Indonesia / Indonésia
        "indonésia" | "indonesia" | "id" | "idn" => (-0.78, 113.92),

        // Malaysia / Malásia
        "malásia" | "malasia" | "malaysia" | "my" | "mys" => (4.21, 101.97),

        // Thailand / Tailândia
        "tailândia" | "tailandia" | "thailand" | "th" | "tha" => (15.87, 100.99),

        // Pakistan / Paquistão
        "paquistão" | "paquistao" | "pakistan" | "pk" | "pak" => (30.37, 69.34),

        // Philippines / Filipinas
        "filipinas" | "philippines" | "ph" | "phl" => (12.87, 121.77),

        // New Zealand / Nova Zelândia
        "nova zelândia" | "nova zelandia" | "new zealand" | "nz" | "nzl" => (-40.90, 174.88),

        // United Arab Emirates / Emirados Árabes Unidos
        "emirados árabes unidos" | "emirados arabes unidos" | "united arab emirates" | "uae"
        | "ae" | "are" => (23.42, 53.84),

        // Saudi Arabia / Arábia Saudita
        "arábia saudita" | "arabia saudita" | "saudi arabia" | "sa" | "sau" => (23.88, 45.07),

        // Morocco / Marrocos
        "marrocos" | "morocco" | "ma" | "mar" => (31.79, -7.09),

        // Angola
        "angola" | "ao" | "ago" => (-11.20, 17.87),

        // Mozambique / Moçambique
        "moçambique" | "mocambique" | "mozambique" | "mz" | "moz" => (-18.66, 35.52),

        // Cape Verde / Cabo Verde
        "cabo verde" | "cape verde" | "cv" | "cpv" => (16.00, -24.01),

        // Default: (39.5, -8.0) Portugal for unknown, local networks, or fallback
        _ => (39.5, -8.0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_continent_outlines_non_empty() {
        let outlines = get_continent_outlines();
        assert!(!outlines.is_empty(), "Continent outlines should not be empty");
        assert!(
            outlines.len() >= 6,
            "Should provide at least the 6 major continental regions, got {}",
            outlines.len()
        );

        for (i, outline) in outlines.iter().enumerate() {
            assert!(
                outline.len() >= 3,
                "Polygon {} has too few vertices: {}",
                i,
                outline.len()
            );
            for &(lat, lon) in outline.iter() {
                assert!(
                    lat >= -90.0 && lat <= 90.0,
                    "Latitude {} out of bounds [-90, 90]",
                    lat
                );
                assert!(
                    lon >= -180.0 && lon <= 180.0,
                    "Longitude {} out of bounds [-180, 180]",
                    lon
                );
            }
        }
    }

    #[test]
    fn test_get_country_centroid_mappings() {
        // Portugal (name and code)
        let pt = get_country_centroid("Portugal");
        assert!((pt.0 - 39.5).abs() < 1.0);
        assert!((pt.1 - (-8.0)).abs() < 1.0);

        let pt_code = get_country_centroid("PT");
        assert_eq!(pt_code, pt);

        // Germany (German, English, code)
        let de1 = get_country_centroid("Alemanha");
        let de2 = get_country_centroid("Germany");
        let de3 = get_country_centroid("de");
        assert_eq!(de1, de2);
        assert_eq!(de1, de3);
        assert!(de1.0 > 47.0 && de1.0 < 56.0, "Germany lat: {}", de1.0);
        assert!(de1.1 > 5.0 && de1.1 < 16.0, "Germany lon: {}", de1.1);

        // United States (Portuguese, English, code)
        let us1 = get_country_centroid("Estados Unidos");
        let us2 = get_country_centroid("United States");
        let us3 = get_country_centroid("US");
        let us4 = get_country_centroid("usa");
        assert_eq!(us1, us2);
        assert_eq!(us1, us3);
        assert_eq!(us1, us4);
        assert!(us1.0 > 24.0 && us1.0 < 50.0, "US lat: {}", us1.0);
        assert!(us1.1 > -130.0 && us1.1 < -60.0, "US lon: {}", us1.1);

        // China (name and code)
        let cn1 = get_country_centroid("China");
        let cn2 = get_country_centroid("CN");
        assert_eq!(cn1, cn2);
        assert!(cn1.0 > 18.0 && cn1.0 < 54.0, "China lat: {}", cn1.0);
        assert!(cn1.1 > 73.0 && cn1.1 < 136.0, "China lon: {}", cn1.1);

        // France, Russia, UK, Spain, Brazil, Japan
        let fr = get_country_centroid("França");
        assert_eq!(fr, get_country_centroid("FR"));
        assert_eq!(fr, get_country_centroid("France"));

        let ru = get_country_centroid("Rússia");
        assert_eq!(ru, get_country_centroid("RU"));

        let gb = get_country_centroid("Reino Unido");
        assert_eq!(gb, get_country_centroid("GB"));
        assert_eq!(gb, get_country_centroid("UK"));

        let es = get_country_centroid("Espanha");
        assert_eq!(es, get_country_centroid("ES"));

        let br = get_country_centroid("Brasil");
        assert_eq!(br, get_country_centroid("BR"));

        let jp = get_country_centroid("Japão");
        assert_eq!(jp, get_country_centroid("JP"));

        // Default fallback for unknown / local network
        let default_pt = (39.5, -8.0);
        assert_eq!(get_country_centroid("Rede Local (Wi-Fi)"), default_pt);
        assert_eq!(get_country_centroid("LAN"), default_pt);
        assert_eq!(get_country_centroid("unknown-fantasy-country"), default_pt);
        assert_eq!(get_country_centroid(""), default_pt);
    }
}
