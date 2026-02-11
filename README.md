# SQL-Injection Lernprojekt (nur lokal & legal)

Dieses kleine Projekt zeigt den Unterschied zwischen:

- **verwundbarer SQL-Abfrage** (String-Konkatenation)
- **sicherer SQL-Abfrage** (Prepared Statements)

> Hinweis: Das ist eine Schulungsumgebung. Nicht öffentlich deployen.

## Start

```bash
python3 app.py
```

Dann im Browser öffnen:

- http://localhost:8000

## Demo

1. Modus **Verwundbar** wählen.
2. Als Nutzername eingeben: `' OR '1'='1`
3. Du siehst mehrere Treffer (Injection-Effekt).

Danach den Modus **Sicher** wählen und dieselbe Eingabe testen.
Dort sollten keine ungewollten Treffer kommen, weil Parameterbindung verwendet wird.

## Dateien

- `app.py`: HTTP-Server + SQLite Demo
