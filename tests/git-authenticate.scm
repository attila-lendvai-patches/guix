;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2020 Ludovic Courtès <ludo@gnu.org>
;;;
;;; This file is part of GNU Guix.
;;;
;;; GNU Guix is free software; you can redistribute it and/or modify it
;;; under the terms of the GNU General Public License as published by
;;; the Free Software Foundation; either version 3 of the License, or (at
;;; your option) any later version.
;;;
;;; GNU Guix is distributed in the hope that it will be useful, but
;;; WITHOUT ANY WARRANTY; without even the implied warranty of
;;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;;; GNU General Public License for more details.
;;;
;;; You should have received a copy of the GNU General Public License
;;; along with GNU Guix.  If not, see <http://www.gnu.org/licenses/>.

(define-module (test-git-authenticate)
  #:use-module (git)
  #:use-module (guix diagnostics)
  #:use-module (guix git)
  #:use-module (guix git-authenticate)
  #:use-module (guix openpgp)
  #:use-module (guix tests git)
  #:use-module (guix tests gnupg)
  #:use-module (guix build utils)
  #:use-module (srfi srfi-1)
  #:use-module (srfi srfi-34)
  #:use-module (srfi srfi-64)
  #:use-module (rnrs bytevectors)
  #:use-module ((rnrs conditions)
                #:select (warning?))
  #:use-module ((rnrs exceptions)
                #:select (with-exception-handler))
  #:use-module (rnrs io ports))

;; Test the (guix git-authenticate) tools.

(define (gpg+git-available?)
  (and (which (git-command))
       (which (gpg-command)) (which (gpgconf-command))))


(test-begin "git-authenticate")

(unless (which (git-command)) (test-skip 1))
(test-assert "unsigned commits"
  (with-temporary-git-repository directory
      '((add "a.txt" "A")
        (commit "first commit")
        (add "b.txt" "B")
        (commit "second commit"))
    (with-repository directory repository
      (let ((commit1 (find-commit repository "first"))
            (commit2 (find-commit repository "second")))
        (guard (c ((unsigned-commit-error? c)
                   (oid=? (git-authentication-error-commit c)
                          (commit-id commit1))))
          (authenticate-commits repository (list commit1 commit2)
                                #:keyring-reference "master")
          'failed)))))

(unless (gpg+git-available?) (test-skip 1))
(test-assert "signed commits, SHA1 signature"
  (with-fresh-gnupg-setup (list %ed25519-public-key-file
                                %ed25519-secret-key-file)
    ;; Force use of SHA1 for signatures.
    (call-with-output-file (string-append (getenv "GNUPGHOME") "/gpg.conf")
      (lambda (port)
        (display "digest-algo sha1" port)))

    (with-temporary-git-repository directory
        `((add "a.txt" "A")
          (add "signer.key" ,(call-with-input-file %ed25519-public-key-file
                               get-string-all))
          (add ".guix-authorizations"
               ,(object->string
                 `(authorizations (version 0)
                                  ((,(key-fingerprint %ed25519-public-key-file)
                                    (name "Charlie"))))))
          (commit "first commit"
                  (signer ,(key-fingerprint %ed25519-public-key-file))))
      (with-repository directory repository
        (let ((commit (find-commit repository "first")))
          (guard (c ((unsigned-commit-error? c)
                     (oid=? (git-authentication-error-commit c)
                            (commit-id commit))))
            (authenticate-commits repository (list commit)
                                  #:keyring-reference "master")
            'failed))))))

(unless (gpg+git-available?) (test-skip 1))
(test-assert "signed commits, default authorizations"
  (with-fresh-gnupg-setup (list %ed25519-public-key-file
                                %ed25519-secret-key-file)
    (with-temporary-git-repository directory
        `((add "signer.key" ,(call-with-input-file %ed25519-public-key-file
                               get-string-all))
          (commit "zeroth commit")
          (add "a.txt" "A")
          (commit "first commit"
                  (signer ,(key-fingerprint %ed25519-public-key-file)))
          (add "b.txt" "B")
          (commit "second commit"
                  (signer ,(key-fingerprint %ed25519-public-key-file))))
      (with-repository directory repository
        (let ((commit1 (find-commit repository "first"))
              (commit2 (find-commit repository "second")))
          (authenticate-commits repository (list commit1 commit2)
                                #:default-authorizations
                                (list (openpgp-public-key-fingerprint
                                       (read-openpgp-packet
                                        %ed25519-public-key-file)))
                                #:keyring-reference "master"))))))

(unless (gpg+git-available?) (test-skip 1))
(test-assert "signed commits, .guix-authorizations"
  (with-fresh-gnupg-setup (list %ed25519-public-key-file
                                %ed25519-secret-key-file)
    (with-temporary-git-repository directory
        `((add "signer.key" ,(call-with-input-file %ed25519-public-key-file
                               get-string-all))
          (add ".guix-authorizations"
               ,(object->string
                 `(authorizations (version 0)
                                  ((,(key-fingerprint
                                      %ed25519-public-key-file)
                                    (name "Charlie"))))))
          (commit "zeroth commit")
          (add "a.txt" "A")
          (commit "first commit"
                  (signer ,(key-fingerprint %ed25519-public-key-file)))
          (add ".guix-authorizations"
               ,(object->string `(authorizations (version 0) ()))) ;empty
          (commit "second commit"
                  (signer ,(key-fingerprint %ed25519-public-key-file)))
          (add "b.txt" "B")
          (commit "third commit"
                  (signer ,(key-fingerprint %ed25519-public-key-file))))
      (with-repository directory repository
        (let ((commit1 (find-commit repository "first"))
              (commit2 (find-commit repository "second"))
              (commit3 (find-commit repository "third")))
          ;; COMMIT1 and COMMIT2 are fine.
          (and (authenticate-commits repository (list commit1 commit2)
                                     #:keyring-reference "master")

               ;; COMMIT3 is signed by an unauthorized key according to its
               ;; parent's '.guix-authorizations' file.
               (guard (c ((unauthorized-commit-error? c)
                          (and (oid=? (git-authentication-error-commit c)
                                      (commit-id commit3))
                               (bytevector=?
                                (openpgp-public-key-fingerprint
                                 (unauthorized-commit-error-signing-key c))
                                (openpgp-public-key-fingerprint
                                 (read-openpgp-packet
                                  %ed25519-public-key-file))))))
                 (authenticate-commits repository
                                       (list commit1 commit2 commit3)
                                       #:keyring-reference "master")
                 'failed)))))))

(unless (gpg+git-available?) (test-skip 1))
(test-assert "signed commits, .guix-authorizations, unauthorized merge"
  (with-fresh-gnupg-setup (list %ed25519-public-key-file
                                %ed25519-secret-key-file
                                %ed25519-2-public-key-file
                                %ed25519-2-secret-key-file)
    (with-temporary-git-repository directory
        `((add "signer1.key"
               ,(call-with-input-file %ed25519-public-key-file
                  get-string-all))
          (add "signer2.key"
               ,(call-with-input-file %ed25519-2-public-key-file
                  get-string-all))
          (add ".guix-authorizations"
               ,(object->string
                 `(authorizations (version 0)
                                  ((,(key-fingerprint
                                      %ed25519-public-key-file)
                                    (name "Alice"))))))
          (commit "zeroth commit")
          (add "a.txt" "A")
          (commit "first commit"
                  (signer ,(key-fingerprint %ed25519-public-key-file)))
          (branch "devel")
          (checkout "devel")
          (add "devel/1.txt" "1")
          (commit "first devel commit"
                  (signer ,(key-fingerprint %ed25519-2-public-key-file)))
          (checkout "master")
          (add "b.txt" "B")
          (commit "second commit"
                  (signer ,(key-fingerprint %ed25519-public-key-file)))
          (merge "devel" "merge"
                 (signer ,(key-fingerprint %ed25519-public-key-file))))
      (with-repository directory repository
        (let ((master1 (find-commit repository "first commit"))
              (master2 (find-commit repository "second commit"))
              (devel1  (find-commit repository "first devel commit"))
              (merge   (find-commit repository "merge")))
          (define (correct? c commit)
            (and (oid=? (git-authentication-error-commit c)
                        (commit-id commit))
                 (bytevector=?
                  (openpgp-public-key-fingerprint
                   (unauthorized-commit-error-signing-key c))
                  (openpgp-public-key-fingerprint
                   (read-openpgp-packet %ed25519-2-public-key-file)))))

          (and (authenticate-commits repository (list master1 master2)
                                     #:keyring-reference "master")

               ;; DEVEL1 is signed by an unauthorized key according to its
               ;; parent's '.guix-authorizations' file.
               (guard (c ((unauthorized-commit-error? c)
                          (correct? c devel1)))
                 (authenticate-commits repository
                                       (list master1 devel1)
                                       #:keyring-reference "master")
                 #f)

               ;; MERGE is authorized but one of its ancestors is not.
               (guard (c ((unauthorized-commit-error? c)
                          (correct? c devel1)))
                 (authenticate-commits repository
                                       (list master1 master2
                                             devel1 merge)
                                       #:keyring-reference "master")
                 #f)))))))

(unless (gpg+git-available?) (test-skip 1))
(test-assert "signed commits, .guix-authorizations, channel-introduction"
  (let* ((result   #true)
         (key1     %ed25519-public-key-file)
         (key2     %ed25519-2-public-key-file)
         (key3     %ed25519-3-public-key-file))
    (with-fresh-gnupg-setup (list key1 %ed25519-secret-key-file
                                  key2 %ed25519-2-secret-key-file
                                  key3 %ed25519-3-secret-key-file)
      (with-temporary-git-repository dir
          `((checkout "keyring" orphan)
            (add "signer1.key" ,(call-with-input-file key1 get-string-all))
            (add "signer2.key" ,(call-with-input-file key2 get-string-all))
            (add "signer3.key" ,(call-with-input-file key3 get-string-all))
            (commit "keyring commit")

            (checkout "main" orphan)
            (add "noise0")
            (add ".guix-authorizations"
                 ,(object->string
                   `(authorizations
                     (version 0)
                     ((,(key-fingerprint key1) (name "Alice"))
                      (,(key-fingerprint key3) (name "Charlie"))))))
            (commit "commit 0" (signer ,(key-fingerprint key3)))
            (add "noise1")
            (commit "commit 1" (signer ,(key-fingerprint key1)))
            (add "noise2")
            (commit "commit 2" (signer ,(key-fingerprint key1))))
        (with-repository dir repo
          (let* ((commit-0 (find-commit repo "commit 0"))
                 (check-from
                  (lambda* (commit #:key (should-fail? #false) (key key1)
                                   (historical-authorizations
                                    ;; key3 is trusted to authorize commit 0
                                    (list (key-fingerprint-vector key3))))
                    (guard (c ((unauthorized-commit-error? c)
                               (if should-fail?
                                   c
                                   (let ((port (current-output-port)))
                                     (format port "FAILURE: Unexpected exception at commit '~s':~%"
                                             commit)
                                     (print-exception port (stack-ref (make-stack #t) 1)
                                                      c (exception-args c))
                                     (set! result #false)
                                     '()))))
                      (format #true "~%~%Checking ~s, should-fail? ~s, repo commits:~%"
                              commit should-fail?)
                      ;; to be able to inspect in the logs
                      (invoke "git" "-C" dir "log" "--reverse" "--pretty=oneline" "main")
                      (set! commit (find-commit repo commit))
                      (authenticate-repository
                       repo
                       (commit-id commit)
                       (key-fingerprint-vector key)
                       #:historical-authorizations historical-authorizations)
                      (when should-fail?
                        (format #t "FAILURE: Authenticating commit '~s' should have failed.~%" commit)
                        (set! result #false))
                      '()))))
            (check-from "commit 0" #:key key3)
            (check-from "commit 1")
            (check-from "commit 2")
            (with-git-repository dir
                `((add "noise 3")
                  ;; a commit with key2
                  (commit "commit 3" (signer ,(key-fingerprint key2))))
              ;; Should fail because it is signed with key2, not key1
              (check-from "commit 3" #:should-fail? #true)
              ;; Specify commit 3 as a channel-introduction signed with
              ;; key2. This is valid, but it should warn the user, because
              ;; .guix-authorizations is not updated to include key2, which
              ;; means that any subsequent commits with the same key will be
              ;; rejected.
              (set! result
                    (and result
                         (let ((signalled? #false))
                           (with-exception-handler
                               (lambda (c)
                                 (cond
                                  ((not (warning? c))
                                   (raise c))
                                  ((formatted-message? c)
                                   (format #true "warning (expected): ~a~%"
                                           (apply format #false
                                                  (formatted-message-string c)
                                                  (formatted-message-arguments c)))
                                   (set! signalled? #true)))
                                 '())
                             (lambda ()
                               (check-from "commit 3" #:key key2)
                               signalled?))))))
            (with-git-repository dir
                `((reset ,(oid->string (commit-id (find-commit repo "commit 2"))))
                  (add "noise 4")
                  ;; set it up properly
                  (add ".guix-authorizations"
                       ,(object->string
                         `(authorizations
                           (version 0)
                           ((,(key-fingerprint key1) (name "Alice"))
                            (,(key-fingerprint key2) (name "Bob"))))))
                  (commit "commit 4" (signer ,(key-fingerprint key2))))
              ;; This should fail because even though commit 4 adds key2 to
              ;; .guix-authorizations, the commit itself is not authorized.
              (check-from "commit 1" #:should-fail? #true)
              ;; This should pass, because it's a valid channel intro at commit 4
              (check-from "commit 4" #:key key2))
            (with-git-repository dir
                `((add "noise 5")
                  (commit "commit 5" (signer ,(key-fingerprint key2))))
              ;; This is not very intuitive: because commit 4 has once been
              ;; used as a channel intro, it got marked as trusted in the
              ;; ~/.cache/, and because commit 1 is one of its parent, it is
              ;; also trusted.
              (check-from "commit 1")
              (check-from "commit 2")
              ;; Should still be fine, but only when starting from commit 4
              (check-from "commit 4" #:key key2))
            (with-git-repository dir
                `((add "noise 6")
                  (commit "commit 6" (signer ,(key-fingerprint key1))))
              (check-from "commit 1")
              (check-from "commit 2")
              (check-from "commit 4" #:key key2))))))
    result))

(unless (gpg+git-available?) (test-skip 1))
(test-assert "signed commits, .guix-authorizations, authorized merge"
  (with-fresh-gnupg-setup (list %ed25519-public-key-file
                                %ed25519-secret-key-file
                                %ed25519-2-public-key-file
                                %ed25519-2-secret-key-file)
    (with-temporary-git-repository directory
        `((add "signer1.key"
               ,(call-with-input-file %ed25519-public-key-file
                  get-string-all))
          (add "signer2.key"
               ,(call-with-input-file %ed25519-2-public-key-file
                  get-string-all))
          (add ".guix-authorizations"
               ,(object->string
                 `(authorizations (version 0)
                                  ((,(key-fingerprint
                                      %ed25519-public-key-file)
                                    (name "Alice"))))))
          (commit "zeroth commit")
          (add "a.txt" "A")
          (commit "first commit"
                  (signer ,(key-fingerprint %ed25519-public-key-file)))
          (branch "devel")
          (checkout "devel")
          (add ".guix-authorizations"
               ,(object->string                   ;add the second signer
                 `(authorizations (version 0)
                                  ((,(key-fingerprint
                                      %ed25519-public-key-file)
                                    (name "Alice"))
                                   (,(key-fingerprint
                                      %ed25519-2-public-key-file))))))
          (commit "first devel commit"
                  (signer ,(key-fingerprint %ed25519-public-key-file)))
          (add "devel/2.txt" "2")
          (commit "second devel commit"
                  (signer ,(key-fingerprint %ed25519-2-public-key-file)))
          (checkout "master")
          (add "b.txt" "B")
          (commit "second commit"
                  (signer ,(key-fingerprint %ed25519-public-key-file)))
          (merge "devel" "merge"
                 (signer ,(key-fingerprint %ed25519-public-key-file)))
          ;; After the merge, the second signer is authorized.
          (add "c.txt" "C")
          (commit "third commit"
                  (signer ,(key-fingerprint %ed25519-2-public-key-file))))
      (with-repository directory repository
        (let ((master1 (find-commit repository "first commit"))
              (master2 (find-commit repository "second commit"))
              (devel1  (find-commit repository "first devel commit"))
              (devel2  (find-commit repository "second devel commit"))
              (merge   (find-commit repository "merge"))
              (master3 (find-commit repository "third commit")))
          (authenticate-commits repository
                                (list master1 master2 devel1 devel2
                                      merge master3)
                                #:keyring-reference "master"))))))

(unless (gpg+git-available?) (test-skip 1))
(test-assert "signed commits, .guix-authorizations removed"
  (with-fresh-gnupg-setup (list %ed25519-public-key-file
                                %ed25519-secret-key-file)
    (with-temporary-git-repository directory
        `((add "signer.key" ,(call-with-input-file %ed25519-public-key-file
                               get-string-all))
          (add ".guix-authorizations"
               ,(object->string
                 `(authorizations (version 0)
                                  ((,(key-fingerprint
                                      %ed25519-public-key-file)
                                    (name "Charlie"))))))
          (commit "zeroth commit")
          (add "a.txt" "A")
          (commit "first commit"
                  (signer ,(key-fingerprint %ed25519-public-key-file)))
          (remove ".guix-authorizations")
          (commit "second commit"
                  (signer ,(key-fingerprint %ed25519-public-key-file)))
          (add "b.txt" "B")
          (commit "third commit"
                  (signer ,(key-fingerprint %ed25519-public-key-file))))
      (with-repository directory repository
        (let ((commit1 (find-commit repository "first"))
              (commit2 (find-commit repository "second"))
              (commit3 (find-commit repository "third")))
          ;; COMMIT1 and COMMIT2 are fine.
          (and (authenticate-commits repository (list commit1 commit2)
                                     #:keyring-reference "master")

               ;; COMMIT3 is rejected because COMMIT2 removes
               ;; '.guix-authorizations'.
               (guard (c ((unauthorized-commit-error? c)
                          (oid=? (git-authentication-error-commit c)
                                 (commit-id commit2))))
                 (authenticate-commits repository
                                       (list commit1 commit2 commit3)
                                       #:keyring-reference "master")
                 'failed)))))))

(test-end "git-authenticate")
