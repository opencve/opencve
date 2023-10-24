for VAR in 14 15 16 17 18 19 20 21 22
do

airflow tasks test updater parsers.parse_mitre 2023-10-23T$VAR:00:00+00:00
airflow tasks test updater parsers.parse_nvd 2023-10-23T$VAR:00:00+00:00
airflow tasks test updater reports.get_changes 2023-10-23T$VAR:00:00+00:00
airflow tasks test updater reports.get_subscriptions 2023-10-23T$VAR:00:00+00:00
airflow tasks test updater reports.populate_reports 2023-10-23T$VAR:00:00+00:00

done
