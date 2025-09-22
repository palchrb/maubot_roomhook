# maubot_roomhook
A maubot plugin for room specific webhooks configurable from any room

There are already maubot webhook plugins, but I could mainly find versions that predominantly think that the maubot admin is the only user of the webhooks (with auth and all defined here, and no !help dialogue with the clients). But I wanted to have a webhook bot that my server's users can set up themselves, with authentication and all per room with just talking to the webhook bot. So that is what I have tried to do here!

Code is not beatiful, but it seems to work (but all functions are not battle tested yet, e.g. the jinja templating i have yet to fully try out)

So this bot will allow you to;
- Invite the bot
- !webhook add "name" to generate a webhook config with bearer token, specific to this room only
- full url with tokens displayed, both with the option to use bearer token and inline url token if that is what is needed for your service

You can define in your config;
- Only allow users from your homeserver to use this bot
- PL needed to use bot
- PLus a bit more; this is not fully polished

Works in v12 rooms since Maubot works in v12 rooms..

Feel free to contact me [on Matrix](https://matrix.to/#/@palchrb:vibb.me)
