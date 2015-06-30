There are two ways to customize Durbatulûk.  The first option is very easy and reliable if you have a modest bit of money.  The second option is not too hard if you or someone who owes you a favor is a competent programmer.

## Option One ##

Hire me to customize Durbatulûk for you.  You can find information about contacting me directly [here](http://goo.gl/7KUQc).

## Option Two ##

The Durbatulûk [license](Legal.md) allows you to customize Durbatulûk for your own needs.  The software is designed to be relatively easy for an experienced C++ programmer to customize as the logic for handling messages is encapsulated in the MessageHandler class.

To customize Durbatulûk, look at closely at MessageHandler::HandleMessage.  This is a somewhat monolithic method where handling of messages takes place.