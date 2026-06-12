Scanner Hardlink - YOHSS

Une fenêtre (WPF / . NET 8) outil médico-légal qui énumère ** groupes de liens durs NTFS** sur un volume,
résout chaque chemin qui pointe vers chaque fichier sous-jacent, vérifie le code authentique de chaque fichier
signature** (et *qui* l'a signée), exclut **éditeurs légitimes** (Microsoft, etc.), et
exécute **règles YARA configurables** contre les fichiers liés - le tout dans une interface utilisateur sombre de style scanner.

C'est la contrepartie défensive de l'astuce du "remplacer-via-hardlink": ces contournements se cachent de
le journal USN, mais le lien existe toujours dans le système de fichiers en direct pendant son utilisation, donc un
Activation MFT/filesystem en direct.

> **Note de portée :** ceci se lit dans le système de fichiers **live**. Un lien dur qui a déjà été
> *supprimé* ne laisse rien ici pour trouver - récupérer ces besoins '$LogFile', instantanés VSS,
> ou la sculpture MFT brute, ce que cet outil ne fait pas.

---

## Qu'est-ce qu'il fait

1. ** Énumérer les liens durs.** Marche dans l'arbre cible, et pour chaque fichier dont le lien NTFS compte
'> 1' il répertorie *tous* ses chemins via 'FindFirstFileNameW' / 'FindNextFileNameW',
désdupliquer les groupes par id de fichier 64 bits. (Les points de réparation / jonctions sont ignorés.)
2. **Vérifier les signatures.** Le fichier sous-jacent de chaque groupe est coché avec 'WinVerifyTrust'
(Le fichier correspond-il réellement à sa signature et à sa chaîne à une racine de confiance ?) et le signataire
org/CN est extrait.
3. **Exclure les fichiers légitimes.** Fichiers signés * et approuvés* par un éditeur dans votre liste blanche
(Microsoft par défaut) sont filtrés - à moins qu'une règle YARA ne soit toujours appliquée.
4. **YARA.** Coint vers 'yara64.exe' avec votre fichier de règles. Entièrement configurable ; pas de natif
liant au navire.

Des rangées suspectes (non signées, signées mais non dignes de confiance, non inscrites sur la liste blanche, ou tout autre succès de YARA) sont montrées
en rouge.

## Exigences

- Volume Windows 10/11, **NTFS**.
- **. NET 8 SDK** à construire ('dotnet build'), ou à ouvrir dans Visual Studio 2022.
- Exécute ** en tant qu'administrateur** (le manifeste le force) afin qu'il puisse lire les chemins protégés et
Vérifiez les signatures partout.
- Pour YARA : téléchargez 'yara64.exe' depuis les versions officielles de YARA et mettez-le sur 'PATH'
ou définissez son chemin complet dans l'interface utilisateur / 'config.json'. S'il manque, YARA est juste ignorée.

## Construire et exécuter

'PowerShell
cad HardlinkScanner
dotnet build -c Release
# puis exécuter l'exe produit élevé :
.\bin\Release\net8.0-windows\HardlinkScanner.exe
"'

Configuration ## (config.json)

Clé | Signification |
|--------------------|----------------------------------------------------------------|
'Éditeurs de confiance'| Sous-chaînes de signes considérées comme légitimes et exclues. |
'YaraExePath' | Chemin vers 'yara64.exe' (ou simplement le nom si sur 'PATH'). |
'YaraRulesPath' | Chemin vers votre fichier de règles '.yar' / '.yara'. |
'ExcludeTrusted' | Masquer les fichiers en liste blanche/de confiance (YARA frappe encore la surface). |
'Only Show Suspicious'| Cachez tout ce qui n'est pas signalé. |

L'interface utilisateur les écrit à chaque scan.

## Notes / mises en garde honnêtes

Je ne pouvais pas compiler ou exécuter ceci sur Windows à partir de l'endroit où il a été généré, alors traitez-le comme un
point de départ solide et complet - attendez-vous à le construire et éventuellement à lisser un bord rugueux
(l'interop 'WinVerifyTrust' et la gestion de tampon 'FindFirstFileNameW' sont les plus efficaces)
pots susceptibles de vouloir un second regard.
Une marche complète 'C :\' est **O (tous les fichiers) ** - assez rapide pour le triage mais pas instantanée. Scanner un
Le dossier spécifique est beaucoup plus rapide. Si vous voulez une vitesse brute-MFT plus tard, la couche d'énumération
('HardlinkEnumerator') est isolé et peut être échangé contre un lecteur MFT sans toucher le
Repos.
Tous les fichiers d'un groupe de liens durs partagent des octets identiques, de sorte que l'analyse de signature/YARA est effectuée
une fois par groupe. 
