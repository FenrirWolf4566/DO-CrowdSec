# Introduction

La sécurité dans le DevOps est un gros enjeu, car comme le reste il faut l'intégrer dans le cycle et la rendre automatique et systéma
tique. Ce qui n'est pas une chose aisée, car longtemps délaissé et les développeurs ne sont pas forcément en recherche de risque 0. C'est pourquoi il est important de rendre ce cycle sûr.

La sécurité dans le cycle DevOps peut intervenir à n'importe quel endroit : le code, le test, le déploiement, le monitoring ,.... Chaque étape demande des niveaux d'exigences différents. 

Cette pullrequest à pour but de présenter quelques outils qu'on à juger important à mettre en place dans une logique de DevOps. 

Ce tuto à été fait par **Quentin Le Lan, Marius Le Douarin, Quentin Le Grand, Benjamin Dezordo**.

Nous allons vous présenter des outils d'analyse statique et d'analyse dynamique qui sont donc complémentaire en matière de sécurité. 


- [Introduction](#introduction)
- [Scanner Docker](#scanner-docker)
  - [Dockle](#dockle)
  - [Docker Bench For Security](#docker-bench-for-security)
- [CrowdSec](#crowdsec)
  - [Introduction à l’outil CrowdSec](#introduction-à-loutil-crowdsec)
  - [Fil d’Arianne](#fil-darianne)
    - [Problématique](#problématique)
  - [Mise en place de la solution](#mise-en-place-de-la-solution)
    - [Informations](#informations)
    - [Créer son compte](#créer-son-compte)
    - [Installation](#installation)
    - [Tableau de bord](#tableau-de-bord)
    - [Scenarios](#scenarios)
    - [Alertes](#alertes)
    - [Bouncers](#bouncers)
    - [Les commandes](#les-commandes)
  - [Références](#références)
- [Conclusion](#conclusion)



# Scanner Docker 

Pourquoi sécuriser Docker ? Parce que c'est l'environnement de production et du développement. Si Docker est protégé correctement alors le risque d'accident en prod est réduit. 

Il existe de nombreux scanner d'image docker, certain plus complet ou plus simple d'utilisation. Ce sont des scanners statiques, c'est à dire qu'ils vont analyser votre image une fois construite pour vous donner des indications sur les bonnes pratiques ou les failles de sécurité de ces dernières. Nous allons en voir 2. 

## Dockle

Dockle est un scanner d'image open source [Dockle](https://github.com/goodwithtech/dockle#debianubuntu).  

Pour l'installer rien de plus simple, il suffit de prendre l'explication sur leur page officielle, nous allons prendre celle pour Ubuntu. 

```sh
VERSION=$(
 curl --silent "https://api.github.com/repos/goodwithtech/dockle/releases/latest" | \
 grep '"tag_name":' | \
 sed -E 's/.*"v([^"]+)".*/\1/' \
) && curl -L -o dockle.deb https://github.com/goodwithtech/dockle/releases/download/v${VERSION}/dockle_${VERSION}_Linux-64bit.deb
$ sudo dpkg -i dockle.deb && rm dockle.deb
```

Et voila ! Dockle est installé. 
Maintenant il vous suffit de faire un 

```sh
$ sudo docker image ls
```
Ce qui va vous lister toutes vos images Docker présentent sur votre ordinateur. 

Puis vous pouvez en choisir une et faire 
```sh
$ dockle [image name]
```

Vous allez vous retrouverer avec toute une sortie d'information comme par exemple :

```
WARN	- DKL-DI-0006: Avoid latest tag
	* Avoid 'latest' tag
INFO	- CIS-DI-0005: Enable Content trust for Docker
	* export DOCKER_CONTENT_TRUST=1 before docker pull/build
INFO	- CIS-DI-0006: Add HEALTHCHECK instruction to the container image
	* not found HEALTHCHECK statement
```

Dockle utilise 5 niveaux d'information : FATAL, WARN, INFO, SKIP, PASS, qui est du plus grave au moins grave. 
Il va réussir à pointer les choses qui ne sont pas correctes, cependant il peut ne pas être très verbeux concernant les choses à faire exactement pour fixer les issues. 

Vous trouverez tous les tags que Dockle reconnait [ici](https://github.com/goodwithtech/dockle/blob/master/CHECKPOINT.md)
Vous pouvez avoir les informations en SARIF ou en JSON en sortie avec l'option -f ce qui donne : 
```sh
$ dockle -f sarif [image name]
```
Vous pouvez aussi enregistrer ces informations avec l'option -o

Il serait possible d'intégrer cet outil dans une CI (gitlab par exemple) pour pouvoir analyser directement les images construites dans celle-ci. Ce qui est tout l'intérêt du DevSecOps, c'est d'avoir des techniques automatiques pour faire des scans de sécurités. Si on peut l'intégrer dans une CI pour vérifier que les images construites vont bien être déployées sans aucune faille cela est un point très positif. 

## Docker Bench For Security

[Docker Bench For Security](https://github.com/docker/docker-bench-security)
Un autre scan qui peut être intéressant de faire c'est le Docker Bench for Security parce qu'il ne scan pas que les images. En effet alors que Dockle scan que les images, le docker bench security peut scanner le host, le docker deamon, les images et le conteuneur runtime. 

C'est un simple script shell mais qui ne peut s'éxecuter qu'en local (donc pas CI). 

Pour l'utiliser : 
```sh
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```

Ce qui peut vous donner ce type de sortie : 

```
[WARN] 1.1.1 - Ensure a separate partition for containers has been created (Automated)
[INFO] 1.1.2 - Ensure only trusted users are allowed to control Docker daemon (Automated)
[INFO]       * Users: 
[WARN] 1.1.3 - Ensure auditing is configured for the Docker daemon (Automated)
[WARN] 1.1.4 - Ensure auditing is configured for Docker files and directories -/run/containerd (Automated)
[WARN] 1.1.5 - Ensure auditing is configured for Docker files and directories - /var/lib/docker (Automated)
```
Comme pour Dockle on va retrouver différents tags en fonction de l'importance de la faille : WARN, INFO, NOTICE, PASS. Ce scan sera moins efficace pour les images mais pour les autres éléments de docker il peut être très intéressant. Les conseils donnés sont plutôt clairs. 
Un désavantage de ce scan c'est qu'on ne peut pas choisir quel élément ou image scanner, si on le lance on est obligé d'attendre que tout soit scanné. 

Ces 2 scans permettent de faire de l'audit de securité mais aussi du scan de bonne pratique. Certains scans sont dédiés seulement aux bonnes pratiques comme [Hadolin](https://github.com/hadolint/hadolint)

Bien qu'un scan soit déjà un bon début dans la sécurité dans le DevOps cela n'est en rien suffisant, tout d'abord parce que ce sont des scans statiques (donc on ne sait pas si il y a un problème pendant que le conteneur est déployé) et surtout que la sécurité ici est basé que sur les conteneurs, mais on peut aussi trouver des outils pour protéger d'autre élément du cycle DevOps, comme vault pour protéger les crédentials (mot de passe de bdd, les .env, ...). Nous avons essayé de le mettre en place mais il n'était compatible avec aucune de nos projets.
Les scans sont une première étape mais doivent être complétés avec d'autres outils pour couvrir et sécurisés entièrement le cycle DevOps.

# CrowdSec

## Introduction à l’outil CrowdSec

>“Make the internet a safer place for everyone” - CrowdSec

CrowdSec est un outil de monitoring de sécurité gratuit et opensource.

Il a été développé grâce à la collaboration d’anciens consultants d’horizons différents (Sysadmins, DevOps et SecOps) ce qui est l’essence même de la philosophie DevOps.

Le but de cet IPS (Intrusion Prevention System) est de proposer une sécurité personnalisée et relativement simple d’accès. Elle pourra notamment :

- détecter des cyber attaques puis de prendre des décisions,
- automatiser ces tâches,
- fournir un centre de contrôle cyber,
- rendre sécurité accessible à tous,
- créer une communauté active contre le HackOps (automatisation des procédés de hacking).

[CrowdSec - The open-source & collaborative IPS](https://www.crowdsec.net/)



## Fil d’Arianne

Le DevOps est certe une philosophie mais aussi un chantier sur lequel se trouve de multiples outils interagissant entre eux. Malheureusement, ces outils peuvent être la cause de failles de sécurité (CVE) et des protections réseaux ne sont pas mis en place.

### Problématique

Comment ajouter une sécurité à notre système DevOps pour être notifiée en cas de failles ou de comportement malicieux et même prendre des décisions de façon automatisé ?


## Mise en place de la solution

### Informations

Voici les différents systèmes sur lequel CrowdSec est déployable : 

- Linux (Debian, Ubuntu, EL/Centos7, EL/Centos Stream 8, Amzn Linux 2, OpenWRT, CloudLinux),
- FreeBSD,
- OPNsense,Version Docker
- Helm/K8s,
- Windows

Vous retrouverez un tutoriel pour chacun des systèmes de la liste ci-dessus sur le site de CrowdSec ([Installation CrowdSec](https://docs.crowdsec.net/docs/getting_started/install_crowdsec/)).

Il existe également une solution Docker disponible ici . Néanmoins cette solution est assez pesteuse, aussi nous nous concentrerons sur une installation classique : [Docker CrowdSec](/Docker_CrowdSec.md)


### Créer son compte

En allant sur le site de [CrowdSec](https://doc.crowdsec.net/) vous trouverez en haut un onglet “Console” accessible [ici](https://app.crowdsec.net/signup).

Vous devrez vous créer un compte sur le site. Une fois toutes les conditions remplies, vous tomberez sur la console :

![login.png](/assets/login.png)

Il sera cessaire de choisir une des catégories puis de renseigner le nombre de collaborateurs qui utilisera le logiciel.

### Installation

Une fois connecté à la console, un tutoriel vous attend afin d’installer CrowdSec sur votre serveur :

```bash
curl  -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | sudo bash
sudo apt-get  install crowdsec
sudo apt  install crowdsec-firewall-bouncer-iptables
sudo cscli  console enroll [key]
```

La dernière commande vous permet d’établir la connexion entre votre serveur et la console.

![enroll.png](/assets/enroll.png)

### Tableau de bord

Vous voilà sur ce centre de contrôle, nous allons voir à quoi correspondent chaque item.

![serveur.png](/assets/enroll.png)

- **Scenarios** : un scénario est un ensemble de règles qui décrivent un comportement potentiellement nuisible (exemple : tentatives de connexion infructueuses, DDOS, scans de port),
- **Agent** : un programme qui permet de surveiller les activités du serveur en fonction des scénarios introduit,
- **Alertes** : lorsqu’un agent détecte une activité suspecte via scénario, une alerte est générée,
- **Bouncer** : logiciels autonomes chargés de prendre une décision suite à une alerte : bloquer une IP, présenter un captcha, appliquer le MFA à un utilisateur donné, etc…
- **Blocklist** : établir une blacklist pour bloquer l’accès à certain IP (certaines listes sont déjà construites et prête à être utilisées).

### Scenarios

Initialement 35 scénarios sont déjà déployés, nous allons en voir quelques uns.

**Quelques exemples :** 

- **[fortinet-cve-2018-13379](https://hub.crowdsec.net/author/crowdsecurity/configurations/fortinet-cve-2018-13379) et [grafana-cve-2021-43798](https://hub.crowdsec.net/author/crowdsecurity/configurations/grafana-cve-2021-43798) :** Ce type de scénario a pour but de bloquer les attaques profitant d’une faille répertoriée CVE (Common Vulnerability and Exploit).

- **[http-xss-probing](https://hub.crowdsec.net/author/crowdsecurity/configurations/http-xss-probing) :** vise à détecter, avec très peu de chances de faux positifs, les tentatives de détection XSS (les failles XSS ou Cross-Site Scripting est une injection dans l’URL).

- **[ssh-slow-bf](https://hub.crowdsec.net/author/crowdsecurity/configurations/ssh-slow-bf)** : Détecte les authentifications ssh lentes par bruteforce.


**Comment en ajouter ? :**

Il est possible d’ajouter des scénarios déjà existant via une base de données ([ici](https://hub.crowdsec.net/browse/)) ou bien créer ses propres scénarios afin de répondre aux besoins spécifiques que l’on aurait. Pour cela, CrowdSec a créé un [tutoriel](https://www.notion.so/CrowdSec-12173c34db2e416db7216ba3b8759751).

D’autre part il est possible de partager ses scénarios avec le reste des utilisateurs, c’est la force de CrowdSec.

### Alertes

En cliquant sur le module d’alerte, nous obtenons une liste des traces malveillantes que le/les agent(s) ont détectés en fonction des scénarios.

![alert_monitor.png](/assets/alert_monitor.png)

Ci-dessus est présenté la fenêtre de Visualisation permettant de voir quelques informations tel que  :

- les IPs qui ont tenté de communiquer avec votre serveur,
- les sources AS (Autonomous System) d'où provient le trafic ou l'attaque,
- les agents qui ont détecté une présence,
- les scénarios qui ont été activés.

Un peu plus bas, nous retrouvons une liste complète de chaque potentielle attaque dans laquelle nous retrouvons chacune des informations vues ci-dessus.

![alert_list.png](/assets/alert_list.png)

### Bouncers

Il est également possible d’ajouter des bouncers, d’ailleur un [tutoriel](https://blog.raspot.in/fr/blog/crowdsec-ajout-et-configuration-dun-bouncer) à été écrit a ce propos.

Installation d’un Bouncer :

1. **Obtenir le nom du bouncer**
Chercher un bouncer : [https://hub.crowdsec.net/browse/#bouncers](https://hub.crowdsec.net/browse/#bouncers)
Nous utiliserons le : **cs-nginx-bouncer**
2. **Ajouter le bouncer au serveur**
`cscli bouncers add cs-nginx-bouncer`
3. (Pour certains Bouncers) Association de la clé API
Toujours sur le serveur se rendre sur : `cd /etc/crowdsec/bouncers/`
Ecrire la clé API : `nano cs-nginx-bouncer.yml`

Votre Bouncer est installé !

### Les commandes

Vous pouvez utilisé la commande `cscli` sur le serveur où a été instalé CrowdSec, voici une liste des paramètres utilisable :

```bash
alerts         Manage alerts
bouncers       Manage bouncers [requires local API]
capi           Manage interaction with Central API (CAPI)
collections    Manage collections from hub
completion     Generate completion script
config         Allows to view current config
console        Manage interaction with Crowdsec console (https://app.crowdsec.net)
dashboard      Manage your metabase dashboard container [requires local API]
decisions      Manage decisions
explain        Explain log pipeline
help           Help about any command
hub            Manage Hub
hubtest        Run functional tests on hub configurations
lapi           Manage interaction with Local API (LAPI)
machines       Manage local API machines [requires local API]
metrics        Display crowdsec prometheus metrics.
notifications  Helper for notification plugin configuration
parsers        Install/Remove/Upgrade/Inspect parser(s) from hub
postoverflows  Install/Remove/Upgrade/Inspect postoverflow(s) from hub
scenarios      Install/Remove/Upgrade/Inspect scenario(s) from hub
simulation     Manage simulation status of scenarios
support        Provide commands to help during support
version        Display version and exit.
```

---

## Références

| Nom | Source |
| :---: | :---: |
| 2 min pour se protéger des HACKERS - Waked XY | https://www.youtube.com/watch?v=dvqgc8f_2Nw |
| Tracker l'IP des attaquants - Waked XY | https://www.youtube.com/watch?v=j5QnrSJXVrQ |
| Comment protéger son serveur Linux des attaques avec CrowdSec ? | https://www.it-connect.fr/comment-proteger-son-serveur-linux-des-attaques-avec-crowdsec/ |
| [Tuto] Installation et Configuration de CrowdSec avec le reverse proxy SWAG | https://www.forum-nas.fr/threads/tuto-installation-et-configuration-de-crowdsec-avec-le-reverse-proxy-swag.18327/ |
| Crowdsec : Ajout et configuration d'un bouncer | https://blog.raspot.in/fr/blog/crowdsec-ajout-et-configuration-dun-bouncer |
| CrowdSec Hub | https://hub.crowdsec.net/ |

# Conclusion

Nous avons donc pu voir différents outils, des outils de sécurités dynamiques et statiques. Les deux sont bien sur complémentaires. Mais c'est outils interviennent au même endroit du cycle DevOps : Deploy & operate. Pourtant la sécurité se trouve bien à chaque étape du cycle DevOps. La sécurité au sein du DevOps est un processus vaste, long et difficile. Il faut se tenir à jour tout le temps pour connaitre les dernières technologie efficace et les dernières failles découvertes. Ce tuto est un premier pas dans le monde de la sécurité mais il en faudrait un cours tout en entier pour espérer couvrir l'ensemble du cycle DevOps