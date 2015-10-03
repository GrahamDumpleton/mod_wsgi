============
Finding Help
============

If after you have gone through all the available documentation you still
cannot work out how to do something or can't resolve a problem you are
having, use the mod_wsgi mailing list to post your question. The mailing
list is hosted by Google Groups at:

* http://groups.google.com/group/modwsgi

You do not need to have a Google email account as Google Groups allows you
to register external email addresses as well.

Please use the mailing list in preference to raising a ticket in the issue
tracker, unless you are somewhat certain that the problem is a bug in
mod_wsgi and not just some environment issue related to your application,
any third party packages being used or the operating system. It is much
easier to have a discussion on the mailing list than the issue tracker.

The mailing list also has many people participating, or at least reading,
so you have people with a broad experience with many third party Python web
packages and operating systems who may be able to help.

If the problem is potentially more an issue with a third party package or
the operating system rather than mod_wsgi, you might also consider asking
on any mailing list related to the third party package instead.

A further option is to ask your question on StackOverflow, if a programming
question, or ServerFault, if an administration issue. These sites allow a
broad range of questions about many topics with quite a large user base of
sometimes knowledgeable people.

A final option you might try is any IRC channels related to any third party
package or the more general #wsgi.

Do be aware though that the only forum that is guaranteed to be monitored
is the mod_wsgi mailing list. Questions are not gauranteed to be answered
on sites such as StackOverflow and ServerFault, on IRC, or mailing lists
for other packages. So, it is much preferable to use the mod_wsgi mailing
list if you want an informed answer for a mod_wsgi specific question.

As a general rule, if you have never participated in public forums
previously to seek answers to technical questions, including about Open
Source software, it is highly recommended you have a read of.

* http://www.catb.org/esr/faqs/smart-questions.html

This will help you to ensure you have exhausted all possibilities as to
where to find information and try and solve the problem yourself, as well
as assist you in framing your question the best way so as to get the best
response possible.

Remember that people on the mailing list are volunteering their time to
help and don't get paid for answering questions. Thus, it is in your
interest not to annoy them too much.

No matter which forum you use, when asking questions, it is always helpful
to detail the following:

1. Which version of mod_wsgi you are using and if using a packaged
   distribution, who provided the distribution.

   If you are not using the latest version, then upgrade first and verify
   the problem still occurs with the latest version.

2. Which version of Python you are using and if using a packaged
   distribution, who provided the distribution.

3. Which version of Apache you are using and if using a packaged
   distribution, who provided the distribution.

   If not using latest version of Apache available, then consider upgrading
   and trying again. If at all possible, avoid using Apache 2.0 or 2.2. You
   definitely shouldn't still be using Apache 1.3

4. What operating system you are using.

5. Details on any third party packages being used and what versions of
   those packages.

6. The mod_wsgi configuration you are using from Apache configuration files.

   In particular you should indicate whether you are using mod_wsgi
   embedded mode or daemon mode. Also can be helpful to indicate what MPM
   Apache has been compiled for and whether mod_php or mod_python are being
   loaded into the same Apache instance.

7. Relevant error messages from the Apache error logs.

   Specifically, don't just quote the single line you think shows the error
   message. Instead, also show the lines before and after that point. These
   other lines from the error logs may show supplemental error messages
   from Apache or mod_wsgi or provide Python traceback information.
