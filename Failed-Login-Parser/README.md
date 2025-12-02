# Security Log Parser for Failed Login Attempts
## Future Improvements
  - Notification capabilities with syslog functionality
  - Expand scope from just failed login attempts
  - Create timeline tracking functionality
    - If there are 20 attempts from 10 addresses in succesion it is likely the same attacker
  - Configure to be ran by the system by an event (e.g. boot, successful login, before shutdown)
