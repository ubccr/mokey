# Solcon Theme voor Mokey

Een custom Solcon-themed template set voor de Mokey Identity Management applicatie.

## Overzicht

Deze template biedt een volledige Solcon-huisstijl voor Mokey, inclusief:
- Solcon blauwe kleuren (#0055bb)
- Aangepaste header en footer
- Responsive design
- Nederlandse taalondersteuning

## Installatie

### Stap 1: Kopieer bestanden

Kopieer de volgende directories naar je Mokey server:

```bash
# Kopieer de aangepaste templates
cp -r templates/* /etc/mokey/templates/

# Kopieer de CSS
cp static/css/solcon.css /etc/mokey/assets/css/solcon-style.css

# Optioneel: Kopieer het Solcon logo
# Download het Solcon logo van www.solcon.nl en sla op als:
# /etc/mokey/assets/solcon-logo.png
```

### Stap 2: Configureer Mokey

Kopieer het configuratievoorbeeld:

```bash
cp mokey-solcon.toml /etc/mokey/mokey.toml
```

Bewerk `/etc/mokey/mokey.toml` en pas de volgende instellingen aan:

```toml
[site]
name = "Solcon Identity Management"
logo = "/etc/mokey/assets/solcon-logo.png"
css = "/etc/mokey/assets/css/solcon-style.css"
templates_dir = "/etc/mokey/templates"
static_assets_dir = "/etc/mokey/assets"
default_language = "dutch"
```

### Stap 3: Start Mokey opnieuw

```bash
systemctl restart mokey
```

## Directory Structuur

```
solcon-templates/
├── templates/
│   ├── header.html      # Aangepaste header met Solcon navbar
│   └── footer.html      # Aangepaste footer
├── static/
│   └── css/
│       └── solcon.css   # Solcon styling
├── mokey-solcon.toml    # Configuratievoorbeeld
└── README.md
```

## Kleuren

| Kleur | Waarde |
|-------|--------|
| Primair Blauw | #0055bb |
| Donker Blauw | #003d82 |
| Licht Blauw | #1a6ddb |
| Wit/Lichtgrijs | #f8f9fa |
| Tekst | #333333 |

## Functies

### Navbar
- Solcon blauwe gradient achtergrond
- Optioneel logo in de header
- Welkomstbericht voor ingelogde gebruikers

### Login Pagina
- Solcon blauwe header
- Afgeronde hoeken en schaduwen
- Hover effecten op knoppen

### Account Pagina
- Verticale navigatie met Solcon kleuren
- Wit content gebied met afgeronde hoeken
- Icoon-gebaseerde navigatie

### Responsive Design
- Mobiel-vriendelijke layout
- Aangepaste navigatie voor kleine schermen

## Aanpassingen

### Eigen Logo Toevoegen

1. Download het officiële Solcon logo
2. Sla op als `/etc/mokey/assets/solcon-logo.png`
3. Zorg dat het bestand leesbaar is voor mokey:
   ```bash
   chown mokey:mokey /etc/mokey/assets/solcon-logo.png
   chmod 644 /etc/mokey/assets/solcon-logo.png
   ```

### Extra CSS Aanpassingen

Maak een custom CSS bestand aan en voeg het toe aan je `mokey.toml`:

```toml
[site]
css = "/etc/mokey/assets/css/solcon-style.css"
# Voeg je eigen custom CSS toe via:
# additional_css = "/etc/mokey/assets/css/custom.css"
```

## Ondersteunde Pagina's

De Solcon template ondersteunt alle standaard Mokey pagina's:
- Login (`/auth/login`)
- Wachtwoord vergeten (`/auth/forgotpw`)
- Wachtwoord reset (`/auth/reset`)
- Account aanmaken (`/signup`)
- Account beheer (`/account`)
- Wachtwoord wijzigen (`/password`)
- Beveiliging (`/security`)
- SSH Keys (`/sshkey`)
- OTP Tokens (`/otp`)
- Uitloggen (`/auth/logout`)

## Troubleshooting

### Templates worden niet geladen
- Controleer dat `templates_dir` correct staat ingesteld
- Controleer de permissies: `chmod -R 755 /etc/mokey/templates`
- Controleer de logs: `journalctl -u mokey -f`

### CSS wordt niet toegepast
- Controleer dat `css` pad correct is
- Controleer of het CSS bestand leesbaar is
- Browser cache legen

### Logo wordt niet getoond
- Controleer het logo bestandstype (PNG, SVG)
- Controleer de bestandsgrootte (max 500KB aanbevolen)
- Controleer de pad instellingen

## Server Deployment

Voor meerdere servers kun je:

1. **Ansible playbook**: Automatiseer de deployment
2. **Docker**: Gebruik een custom Docker image
3. **GitOps**: Versioneer de templates in een private repository

### Ansible Voorbeeld

```yaml
- name: Deploy Solcon template
  hosts: mokey_servers
  tasks:
    - name: Copy templates
      copy:
        src: templates/
        dest: /etc/mokey/templates/
        owner: mokey
        group: mokey
        mode: 0644
        force: yes

    - name: Copy CSS
      copy:
        src: static/css/solcon.css
        dest: /etc/mokey/assets/css/solcon-style.css
        owner: mokey
        group: mokey
        mode: 0644
        force: yes

    - name: Restart mokey
      systemd:
        name: mokey
        state: restarted
```

## Licentie

Deze template is gebaseerd op de Mokey applicatie en gebruikt de Solcon huisstijl. Raadpleeg de Mokey license voor meer informatie.

## Disclaimer

Dit is een community project en is niet officieel verbonden aan Solcon Internetdiensten B.V. Het logo en de merknaam Solcon zijn eigendom van hun respectievelijke eigenaren.