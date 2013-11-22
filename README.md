INFOF405_Project2
=================

INFO-F405 Computer Security Project 2: Granting Access to Web Services


- pour le client, il lui faudrait une petite "interface" en ligne de commande, du genre "appuyez sur 1 pour accéder au service 1, 2 pour le service 2; appuyez sur X pour afficher les messages de la blackboard, appuyez sur Y pour poster un message, ..." etc. Donc un truc très basique pour intéragir avec les serveurs/services

- php : uniquement pour l'interface web du AS !!

- toutes les appli doivent être en java (donc on aura 4 programmes java : un pour le client, 2 pour les WS et 1 pour le AS)

- le php est pas vraiment "lié" à l'AS, c'est plutôt qu'ils ont tous les 2 accès au même support (que ce soit des fichiers cryptés ou une DB) : l'AS va par ex. lorsqu'il reçoit une connexion d'un client, consulter le fichier ou DB pour voir si le client est autorisé; tandis que l'interface web php consulterait par ex. ce même fichier pour afficher la liste des clients autorisés et l'admin via cette interface php pourrait par ex. en ajouter un nouveau. Vous voyez un peu l'idée?

- pour la connexion réseau entre les divers progs (client, WS, AS), on peut/il est conseillé d'utiliser des librairies toutes faites (donc pas s'amuser à recoder une connexion de A à Z comme on le faisait en TP d'OS l'année passée par exemple)

- pour le client, il y a une étape d'identification d'abord (sur l'idée du "challenge" avec l'AS - le prof a vu ça dans le début du chapitre sur l'identification)

- l'ID du client est distribué par l'admin

- l'ajout d'un client se fait UNIQUEMENT via l'admin qui le rajoute manuellement dans la liste des clients autorisés (via l'interface php) - donc un client quelconque ne sait pas demander à l'AS "tiens, j'aimerais m'enregistrer". Et c'est à ce moment-là que l'admin donne son ID au client ("en personne").
L'exemple que Naim a donné, c'est ~ l'ulb : quand on s'inscrit à l'unif, on reçoit notre ID (matricule) créé par l'admin, et qu'on peut alors utiliser pour accéder aux services.

- le client n'a aucun pass, c'est le "challenge" qui sert d'autentification

- Pour le WS 1 (blackboard), il faudrait stocker les messages postés mais le choix du système est laissé libre, car à voir en fonction du threat modeling lequel est "mieux", et donc j'imagine que stocker en RAM n'est pas une bonne idée  faudrait soit utiliser des fichiers soit une DB sans doute.

- pour le WS 2 (keychain), il s'agit effectivement d'un service où le client peut stocker autant de pass qu'il veut, et doit donc pouvoir les récupérer quand il veut (il doit donc pouvoir insérer, consulter et sans doute retirer ses pass)

