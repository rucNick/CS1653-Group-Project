# CS 1653 Project: Phase 1 Feedback

__Group:__ Black Myth Cryptographer

__Names:__ Cao, Nick; Kaing, Dylan C; Qian, Xingcheng; Acero, Alex

__Users:__ ruc36; dck34; xiq29; ala452

## Comments

### Group information

Good details about your group and roles.

Since you mentioned databases, i will suggest that you consider something like
SQLite rather than attempting to configure a database server on the provided
infrastructure. It's not required but i think it will save a lot of irrelevant
work.

Since your interface seems to be web-based, you may consider creating a client
helper that runs on the provided servers and interacts with the user-specified
authentication server and resource server. That is, since the AS and RS don't
talk directly to one another, neither one can play the role of the **web
server** which provides the code for the front-end and pulls in resources from
the other. You could consider splitting the "client" into two components: The
javascript-based front-end that runs in the browser, and a "coordination server"
(or something) that provides the front-end code and coordinates communication
with the AS and RS, simulating a more native application. Another option could
be to make the client application fully local (e.g., making it a browser
extension or Electron app), so no server has to deliver the client code. In this
case, since the web front-end will communicate directly with the AS and RS, you
will need to implement cryptography in the web browser, which may be an
additional challenge. Either option may require you to use SSH tunneling
(https://linuxconfig.org/introduction-to-ssh-port-forwarding) to enable your
local browser to communicate with the servers that we will make available.

10 / 10

### Design Proposal

A good idea overall, though there are a lot of unspecified details. Will
messages be grouped into threads? How will they be presented? What's stored
about posts, and how are they organized? How are users created, and can they be
deleted?

What information will you store about users? Only the binary flags for whether
they're VIP/admin?

Rather than hardcoding different access levels (guest, normal, VIP, admin), did
you consider using something like tags or categories? This could give you more
flexibility, where adding a user to a category would let them view (and submit)
any posts in that category. This could subsume VIP, and "guests" could be users
without any categories (and thus can only read non-categorized posts). I think
this would be much more interesting and would encourage you to consider it, but
i believe you'll be able to adapt your current approach to the upcoming security
requirements as well, if you feel strongly about keeping it.

40 / 45

### Security Properties

A good number of security properties, though some are very implementation-level
(more mechanism than property). For instance, "Encrypted Login Data" isn't a
security property, it's instead a way for you to *achieve* a particular
property. (In this case, encrypting the login data would achieve the property
that eavesdroppers cannot use what they see to login as other users.) Other
properties that i think have the same issue include: 4, 5, 6, 11, 15, 17

35 / 45

## Overall

Minor: Nice styling, but i couldn't see your logo because of the hardcoded path.
Consider using relative paths.

Good choice of system and good thought put into your security properties, even
though some were a little too implementation-level. I would have liked to see
more details about the system itself (the *what*, not the *how*).

85 / 100