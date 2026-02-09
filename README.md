# Anti-fraude (démo)

Ce mini-programme analyse un fichier CSV de journaux pour signaler des
comportements suspects (bruteforce, paiements élevés, connexions depuis un
nouveau pays).

## Utilisation

```bash
python3 anti_fraude.py ./logs.csv
```

Paramètres utiles :

```bash
python3 anti_fraude.py ./logs.csv --window-minutes 10 --threshold 5 --amount-threshold 500
```

Détection renforcée du credential stuffing :

```bash
python3 anti_fraude.py ./logs.csv --stuffing-window-minutes 15 --stuffing-user-threshold 4
```

## Format CSV attendu

Le fichier doit contenir les colonnes suivantes :

```
timestamp,ip,user,action,status,amount,country
```

Exemple :

```
2024-05-01T10:00:00,192.168.0.1,alice,login,failure,0,FR
```
