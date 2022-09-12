# STAAS Web App
 
 STARTUP DETAILS
 - Note: Database is automatically recreated before first server request when app is initially run (See function recreate_tables in staas_site.py)
 - See requirements.txt for all necessary packages to install in order to run app
 - Run web app with following command: "python staas_site.py"


DESCRIPTION OF OPERATION
- File structure and login functionality modelled after Corey Schafer Flask Blog: https://www.youtube.com/watch?v=MwZwr5Tvyxo&ab_channel=CoreySchafer
- Current Database model (view at top of staas_site.py):
    * USER: user_id (automatically generated), user_name(max. 20 char), email (max. 120 char), password (max. 60 char), is_admin (default == false, for 
      non-Princeton users), flows (automatically set to include all traffic flows created/requested by user)
    * FLOW: 
        ~ name (max. 100 char)
        ~ id (automatically generated)
        ~ flow description
        ~ is_offered (default == true, for flows of admin accounts)
        ~ status (default == active)
        ~ destination address
        ~ destination port
        ~ Source flow
        ~ Start time (automatically set & updated)
        ~ user_id (automatically linked to logged in user at time of creation)
        ~ port type
        ~ payload obfuscation
        ~ selected_traffic
        ~ For admin accounts only (default == 'none', for non-admin accounts): speed, source_address, replication, filters
- MUST restart flask server if changes made to forms.py or to either of the two database models in staas_site.py
