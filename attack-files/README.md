# Descrizione del contenuto di attack-files

## Cartella dnsShell
Questa cartella contiene il codice della Dns Shell che è stata utilizzata all'interno del progetto

## Cartella installer
Questa cartella contiene 
- Il codice eseguibile per installare il run-init malevolo (`installer.sh`)
  Per eseguirlo usare i seguenti comandi nella cartella che contiene il `run-init` infetto:
  ```sh
  chmod +x installer.sh
  sudo ./installer.sh
  ``` 
  Automaticamente viene installato il codice malevolo.

- La versione in byte dell'installer che viene lanciata dal grabber per far sopravvivere l'attacco file `installer.h`

## Files con codice
I file sparsi in questa cartella rappresentano l'insieme di file da dover inserire nella cartella `usr/kinit/run-init` per creare un run-init infetto
Possono essere distinti in due categorie
### Modifiche file originali
I file `KBuild` e `runinitlib.c` sono le versioni modificate degli omonimi file della libreria

### Codice sviluppato
I rimanenti files contengono il codice sviluppato per l'horsepill attack
In particolare:
- Il file `dnscat` contiene la versione in byte del client per il programma DNS shell
- Il file `grabber` contiene il codice che si occupa di far sopravvivere l'attacco ad eventuali aggiornamenti
- Il file `horsepill` contiene il core logico dell'attacco
- Il file `installer` contiene la versione in byte del programma di installazione
