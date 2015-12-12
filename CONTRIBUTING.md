How to submit patches
=====================

Simple Fuzzer has a development email list hosted by google groups,
and can be found at https://groups.google.com/forum/#!forum/sfuzz-devel

Send patch changes as emails to the bytheb.org mailing list at
sfuzz-devel@googlegroups.com; one patch per email, please.

If you are using git, then `git format-patch` does most of the work
described below for you.


Before you start
----------------

Before you send patches, make sure that each patch makes sense. This means
that your patch should:

  - Not break anything. The best way to check this is to make a clean build
    with your patch applied; run the various scripts included and ensure that
    nothing crashes. (This is a good first order test)

  - Make one concise, logical change. Avoid grouping lots of unrelated changes
    together.

  - Update any documentation when new features are added.


Testing your patch is important.


Email Subject
-------------

The subject line of your email should be in the following format:
`[PATCH <n>/<m>] sfuzz: <summary>`

  - `[PATCH <n>/<m>]` indicates that this is the nth of a series
    of m patches.  It helps reviewers to read patches in the
    correct order.  You may omit this prefix if you are sending
    only one patch.

    - `<summary>` briefly describes the change.

The subject, minus the `[PATCH <n>/<m>]` prefix, becomes the first line
of the commit's change log message.

Description
-----------

The body of the email should start with a more thorough description of the
change.  This becomes the body of the commit message, following the subject.
There is no need to duplicate the summary given in the subject.

Please limit lines in the description to 79 characters in width.

The description should include:

  - The rationale for the change.

  - Design description and rationale (but this might be better added as code
    comments).

  - Testing that you performed (or testing that should be done but you could
    not for whatever reason).

  - Tags (see below).

There is no need to describe what the patch actually changed, if the reader can
see it for himself.

Developer's Certificate of Origin
---------------------------------

To help track the author of a patch as well as the submission chain, and be
clear that the developer has authority to submit a patch for inclusion in
Simple Fuzzer please sign off your work.  The sign off certifies the following:

    Developer's Certificate of Origin 1.1

    By making a contribution to this project, I certify that:

    (a) The contribution was created in whole or in part by me and I
        have the right to submit it under the open source license
        indicated in the file; or

    (b) The contribution is based upon previous work that, to the best
        of my knowledge, is covered under an appropriate open source
        license and I have the right under that license to submit that
        work with modifications, whether created in whole or in part
        by me, under the same open source license (unless I am
        permitted to submit under a different license), as indicated
        in the file; or

    (c) The contribution was provided directly to me by some other
        person who certified (a), (b) or (c) and I have not modified
        it.

    (d) I understand and agree that this project and the contribution
        are public and that a record of the contribution (including all
        personal information I submit with it, including my sign-off) is
        maintained indefinitely and may be redistributed consistent with
        this project or the open source license(s) involved.

Patch Signing Tags
------------------

The *Signed-off-by* tag indicates that you were directly involved in the
generation of this patch, either by producing the code, or by influencing it
heavily. Signing off on a change indicates that you take direct responsibility
for that change.

The *Acked-by* tag indicates that you acknowledge the change. It indicates that
you have read the change, understood it, and believe it to be acceptable for
inclusion in the development tree. Acknowledgement usually implies that you
have done a cursory build with the patch. The *Reviewed-by* tag means is the
same as the *Acked-by* but does not imply you have built the change.

The *Tested-by* tag indicates anyone who has applied the code change to their
tree, compiled with the change, and executed the functionality being
manipulated.

The *Reported-by* tag indicates a user that was responsible for reporting a
bug in the code.

Comments
--------

If you want to include any comments in your email that should not be
part of the commit's change log message, put them after the
description, separated by a line that contains just `---`.  It may be
helpful to include a diffstat here for changes that touch multiple
files.

Patch
-----

The patch should be in the body of the email following the description,
separated by a blank line.

Patches should be in `diff -up` format.  We recommend that you use Git
to produce your patches, in which case you should use the `-M -C`
options to `git diff` (or other Git tools) if your patch renames or
copies files.  Quilt (http://savannah.nongnu.org/projects/quilt) might
be useful if you do not want to use Git.

Patches should be inline in the email message.  Some email clients
corrupt white space or wrap lines in patches.  There are hints on how
to configure many email clients to avoid this problem at:
http://git.kernel.org/?p=linux/kernel/git/torvalds/linux-2.6.git;a=blob_plain;f=Documentation/email-clients.txt
If you cannot convince your email client not to mangle patches, then
sending the patch as an attachment is a second choice.
