#!/usr/bin/perl -w

## Ecrit par Guillaume REYNAUD (Administrateur Réseau)
## V1.0 (16/01/2026) : Mise en place dans Icinga.
## V1.1 (19/01/2026) : Correction du filtre GREP pour n'autoriser que le log de dépassement de bande passante ($cmd = q{tac /var/log/ltm 2>/dev/null | grep -m1 '01010045:5: Bandwidth utilization' || true};)
##

use strict;
use warnings;
use Net::OpenSSH;
use Time::Local;
use Getopt::Long;

# Codes de retour Icinga/Nagios
use constant {
    OK       => 0,
    WARNING  => 1,
    CRITICAL => 2,
    UNKNOWN  => 3,
};

# Variables par défaut
my $bigip_host;
my $bigip_user = $ENV{'BIGIP_USER'} || 'admin';
my $bigip_pass = $ENV{'BIGIP_PASS'} || '';
my $ssh_key = $ENV{'BIGIP_SSH_KEY'} || '';
my $warning = 75;
my $critical = 80;
my $age_no_alert = 10;
my $age_alert = 5;
my $help;
my $debug = 0;

# Récupération des options
GetOptions(
    'H|host=s'        => \$bigip_host,
    'u|user=s'        => \$bigip_user,
    'p|password=s'    => \$bigip_pass,
    'k|key=s'         => \$ssh_key,
    'w|warning=i'     => \$warning,
    'c|critical=i'    => \$critical,
    'age-no-alert=i'  => \$age_no_alert,
    'age-alert=i'     => \$age_alert,
    'debug|d'         => \$debug,
    'help'            => \$help,
) or usage();

usage() if $help;

# Validation des paramètres
unless ($bigip_host) {
    print "UNKNOWN - L'option --host est obligatoire\n";
    usage();
}

if ($warning >= $critical) {
    print "UNKNOWN - Le seuil WARNING ($warning) doit être inférieur au seuil CRITICAL ($critical)\n";
    exit UNKNOWN;
}

if ($age_alert >= $age_no_alert) {
    print "UNKNOWN - age-alert ($age_alert) doit être inférieur à age-no-alert ($age_no_alert)\n";
    exit UNKNOWN;
}

# Fonction principale
sub main {
    my ($output, $percent, $bandwidth_used, $bandwidth_licensed);
    
    eval {
        # Connexion SSH au BigIP
        my %ssh_opts = (
            user => $bigip_user,
            timeout => 30,
            kill_ssh_on_timeout => 1,
            master_opts => [
                -o => "StrictHostKeyChecking=no",
                -o => "UserKnownHostsFile=/dev/null",
                -o => "LogLevel=ERROR",
                -o => "ConnectTimeout=10",
                -o => "ServerAliveInterval=5",
                -o => "ServerAliveCountMax=2"
            ]
        );
        
        # Ajouter la clé SSH ou le mot de passe
        if ($ssh_key && -f $ssh_key) {
            $ssh_opts{key_path} = $ssh_key;
        } elsif ($bigip_pass) {
            $ssh_opts{password} = $bigip_pass;
        }
        
        my $ssh = Net::OpenSSH->new($bigip_host, %ssh_opts);
        
        if ($ssh->error) {
            die "Erreur de connexion SSH: " . $ssh->error;
        }
        
        # Exécution de la commande
        # Chercher spécifiquement les logs de dépassement de bande passante (01010045)
        my $cmd = q{tac /var/log/ltm 2>/dev/null | grep -m1 '01010045:5: Bandwidth utilization' || true};
        my $log_line = $ssh->capture($cmd);
        
        # Vérifier les erreurs SSH critiques (mais pas le code de sortie de grep)
        if ($ssh->error && $ssh->error !~ /child exited with code/) {
            die "Erreur lors de l'exécution de la commande: " . $ssh->error;
        }
        
        # Nettoyer la ligne (enlever les espaces et sauts de ligne)
        if (defined $log_line) {
            $log_line =~ s/^\s+|\s+$//g;  # Trim whitespace
        }
        
        if ($debug) {
            print STDERR "DEBUG: Résultat de la commande: '" . (defined $log_line ? $log_line : 'undef') . "'\n";
            print STDERR "DEBUG: Longueur: " . (defined $log_line ? length($log_line) : 0) . "\n";
        }
        
        # Vérifier si on a trouvé une ligne avec 'Licensed'
        if (!defined $log_line || $log_line eq '' || $log_line !~ /01010045:5: Bandwidth utilization/i) {
            # Aucun dépassement trouvé dans les logs - tout est OK
            if ($debug) {
                print STDERR "DEBUG: Aucune ligne de dépassement de bande passante (01010045) trouvée dans /var/log/ltm\n";
            }
            print "OK - Aucun historique de dépassement de bande passante trouvé dans les logs | bandwidth_percent=0%;${warning};${critical};0;150\n";
            exit OK;
        }
        
        # Parse de la ligne de log
        # Format attendu: Jan 15 11:10:38 BIGIP-CLOUD notice tmm[126422]: 01010045:5: Bandwidth utilization is 1070 Mbps, exceeded 75% of Licensed 1000 Mbps.
        # On vérifie d'abord que c'est bien le bon type de log (01010045)
        if ($log_line =~ /01010045:5: Bandwidth utilization is (\d+) Mbps.*Licensed (\d+) Mbps/) {
            my ($used, $licensed) = ($1, $2);
            
            # Calculer le vrai pourcentage d'utilisation
            if ($licensed == 0) {
                die "Bande passante licenciée est 0, impossible de calculer le pourcentage";
            }
            
            my $percent = sprintf("%.2f", ($used / $licensed) * 100);
            
            # Extraire la date du log
            my $date_str;
            if ($log_line =~ /^(\w+\s+\d+\s+\d+:\d+:\d+)/) {
                $date_str = $1;
            } else {
                die "Impossible d'extraire la date du log";
            }
            
            if ($debug) {
                print STDERR "DEBUG: Log trouvé: $log_line\n";
                print STDERR "DEBUG: Date extraite: '$date_str'\n";
                print STDERR "DEBUG: Utilisation: ${used} Mbps / ${licensed} Mbps\n";
                print STDERR "DEBUG: Pourcentage calculé: ${percent}%\n";
            }
            
            $bandwidth_used = $used;
            $bandwidth_licensed = $licensed;
            
            # Vérification de l'âge du log
            my $log_age_minutes = check_log_age($date_str);
            
            if ($debug) {
                print STDERR "DEBUG: Âge du log: ${log_age_minutes} minutes\n";
                print STDERR "DEBUG: age_no_alert=$age_no_alert, age_alert=$age_alert\n";
            }
            
            if ($log_age_minutes > $age_no_alert) {
                # Log trop ancien - pas d'alerte en cours, mettre 0% dans le graphique
                my $age_formatted = format_age($log_age_minutes);
                print "OK - Aucun dépassement récent (dernier: ${percent}% [${used}/${licensed} Mbps] il y a ${age_formatted}) | bandwidth_percent=0%;${warning};${critical};0;150\n";
                exit OK;
            }
            
            # Génération de l'alerte selon le pourcentage et l'âge
            if ($log_age_minutes <= $age_alert) {
                my $age_formatted = format_age($log_age_minutes);
                if ($percent >= $critical) {
                    $output = "CRITICAL - Bande passante à ${percent}% (${used}/${licensed} Mbps) - Alerte il y a ${age_formatted}";
                    print_output($output, $percent, CRITICAL);
                } elsif ($percent >= $warning) {
                    $output = "WARNING - Bande passante à ${percent}% (${used}/${licensed} Mbps) - Alerte il y a ${age_formatted}";
                    print_output($output, $percent, WARNING);
                } else {
                    $output = "OK - Bande passante à ${percent}% (${used}/${licensed} Mbps)";
                    print_output($output, $percent, OK);
                }
            } else {
                # Entre age_alert et age_no_alert - pas d'alerte mais information, 0% dans le graphique
                my $age_formatted = format_age($log_age_minutes);
                $output = "OK - Dernier dépassement à ${percent}% (${used}/${licensed} Mbps) il y a ${age_formatted}";
                print_output($output, 0, OK);
            }
            
        } else {
            # La ligne ne correspond pas au format attendu
            if ($debug) {
                print STDERR "DEBUG: Format de ligne inattendu: $log_line\n";
            }
            die "Format de ligne inattendu: $log_line";
        }
        
    };
    
    if ($@) {
        print "UNKNOWN - Erreur: $@ | bandwidth_percent=U;${warning};${critical};0;150\n";
        exit UNKNOWN;
    }
}

# Fonction pour formater l'âge en JJj:HHh:MMm:SSs
sub format_age {
    my ($minutes) = @_;
    
    my $total_seconds = $minutes * 60;
    
    my $days = int($total_seconds / 86400);
    my $hours = int(($total_seconds % 86400) / 3600);
    my $mins = int(($total_seconds % 3600) / 60);
    my $secs = $total_seconds % 60;
    
    return sprintf("%02dj:%02dh:%02dm:%02ds", $days, $hours, $mins, $secs);
}

# Fonction pour vérifier l'âge du log
sub check_log_age {
    my ($date_str) = @_;
    
    # Format: Jan 15 15:00:05
    # Parser manuellement pour éviter les problèmes de fuseau horaire
    
    # Tableau des mois
    my %months = (
        'Jan' => 0, 'Feb' => 1, 'Mar' => 2, 'Apr' => 3,
        'May' => 4, 'Jun' => 5, 'Jul' => 6, 'Aug' => 7,
        'Sep' => 8, 'Oct' => 9, 'Nov' => 10, 'Dec' => 11
    );
    
    # Parser: Jan 15 15:00:05
    if ($date_str =~ /^(\w+)\s+(\d+)\s+(\d+):(\d+):(\d+)$/) {
        my ($month_str, $day, $hour, $min, $sec) = ($1, $2, $3, $4, $5);
        
        if (!exists $months{$month_str}) {
            die "Mois invalide: $month_str";
        }
        
        my $month = $months{$month_str};
        
        # Obtenir l'année courante
        my @now = localtime(time);
        my $current_year = $now[5] + 1900;
        
        if ($debug) {
            print STDERR "DEBUG: Parsing manuel: mois=$month_str($month), jour=$day, heure=$hour:$min:$sec\n";
            print STDERR "DEBUG: Année courante: $current_year\n";
        }
        
        # Créer le timestamp avec timelocal (pour l'heure locale)
        my $log_epoch = eval {
            timelocal($sec, $min, $hour, $day, $month, $current_year);
        };
        
        if ($@) {
            die "Erreur lors de la création du timestamp: $@";
        }
        
        my $now_epoch = time;
        my $diff_seconds = $now_epoch - $log_epoch;
        
        if ($debug) {
            print STDERR "DEBUG: Epoch du log: $log_epoch (" . scalar(localtime($log_epoch)) . ")\n";
            print STDERR "DEBUG: Epoch actuel: $now_epoch (" . scalar(localtime($now_epoch)) . ")\n";
            print STDERR "DEBUG: Différence: $diff_seconds secondes\n";
        }
        
        # Si le log est dans le futur (changement d'année probable)
        if ($diff_seconds < -3600) {
            if ($debug) {
                print STDERR "DEBUG: Log dans le futur, essai avec année précédente\n";
            }
            
            $log_epoch = timelocal($sec, $min, $hour, $day, $month, $current_year - 1);
            $diff_seconds = $now_epoch - $log_epoch;
            
            if ($debug) {
                print STDERR "DEBUG: Nouvel epoch du log: $log_epoch (" . scalar(localtime($log_epoch)) . ")\n";
                print STDERR "DEBUG: Nouvelle différence: $diff_seconds secondes\n";
            }
        }
        
        my $diff_minutes = int($diff_seconds / 60);
        
        if ($debug) {
            print STDERR "DEBUG: Âge final: $diff_minutes minutes\n";
        }
        
        # Vérifications de sécurité
        if ($diff_minutes < -60) {
            die "L'âge du log est trop négatif ($diff_minutes min). Problème d'heure système ?";
        }
        
        if ($diff_minutes > 525600) {
            die "L'âge du log dépasse un an ($diff_minutes min)";
        }
        
        # Si légèrement négatif (quelques minutes), considérer comme 0
        return $diff_minutes < 0 ? 0 : $diff_minutes;
        
    } else {
        die "Format de date invalide: '$date_str' (attendu: 'Mon DD HH:MM:SS')";
    }
}

# Fonction pour afficher le résultat avec les perfdata
sub print_output {
    my ($message, $percent, $exit_code) = @_;
    
    # Format Icinga avec perfdata pour graphiques
    # bandwidth_percent=valeur%;warning;critical;min;max
    # Max à 150% pour permettre l'affichage des dépassements au-delà de 100%
    print "$message | bandwidth_percent=${percent}%;${warning};${critical};0;150\n";
    exit $exit_code;
}

# Fonction d'aide
sub usage {
    print <<"EOF";
Usage: $0 -H <host> [options]

Options obligatoires:
  -H, --host <IP>           Adresse IP du BigIP

Options d'authentification:
  -u, --user <username>     Nom d'utilisateur SSH (défaut: admin ou \$BIGIP_USER)
  -p, --password <pass>     Mot de passe SSH (défaut: \$BIGIP_PASS)
  -k, --key <path>          Chemin vers la clé privée SSH (défaut: \$BIGIP_SSH_KEY)

Options de seuils:
  -w, --warning <percent>   Seuil WARNING en % (défaut: 75)
  -c, --critical <percent>  Seuil CRITICAL en % (défaut: 80)

Options de temps:
  --age-no-alert <minutes>  Si le log est plus vieux que X minutes, pas d'alerte (défaut: 10)
  --age-alert <minutes>     Si le log est plus récent que X minutes, générer une alerte (défaut: 5)

Autres:
  -d, --debug               Mode debug (affiche les informations de diagnostic)
  --help                    Afficher cette aide

Exemples:
  $0 -H 192.168.3.4
  $0 -H 192.168.3.4 -w 70 -c 85
  $0 -H 192.168.3.4 -u admin -p secret -w 80 -c 90
  $0 -H 192.168.3.4 -k /path/to/key --age-no-alert 15 --age-alert 3

Variables d'environnement:
  BIGIP_USER      Nom d'utilisateur par défaut
  BIGIP_PASS      Mot de passe par défaut
  BIGIP_SSH_KEY   Chemin de la clé SSH par défaut

EOF
    exit UNKNOWN;
}

# Exécution
main();
