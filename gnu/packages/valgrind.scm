;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2013, 2014, 2022 Ludovic Courtès <ludo@gnu.org>
;;; Copyright © 2015 Andreas Enge <andreas@enge.fr>
;;; Copyright © 2015 Mark H Weaver <mhw@netris.org>
;;; Copyright © 2016, 2020 Efraim Flashner <efraim@flashner.co.il>
;;; Copyright © 2018 Tobias Geerinckx-Rice <me@tobias.gr>
;;; Copyright © 2020 Marius Bakke <marius@gnu.org>
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

(define-module (gnu packages valgrind)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix build-system gnu)
  #:use-module (guix licenses)
  #:use-module (gnu packages gdb)
  #:use-module (gnu packages perl)
  #:use-module (gnu packages))

(define-public valgrind
  (package
    (name "valgrind")
    ;; Note: check "guix refresh -l -e '(@ (gnu packages valgrind) valgrind)'"
    ;; when updating this package to find which branch it should go to.
    (version "3.17.0")
    (source (origin
              (method url-fetch)
              (uri (list (string-append "https://sourceware.org/pub/valgrind"
                                        "/valgrind-" version ".tar.bz2")
                         (string-append "ftp://sourceware.org/pub/valgrind"
                                        "/valgrind-" version ".tar.bz2")))
              (sha256
               (base32
                "18l5jbk301j3462gipqn9bkfx44mdmwn0pwr73r40gl1irkfqfmd"))
              (patches (search-patches "valgrind-enable-arm.patch"))))
    (build-system gnu-build-system)
    (outputs '("doc"                              ;16 MB
               "out"))
    (arguments
     `(,@(if (string-prefix? "powerpc" (or (%current-target-system)
                                           (%current-system)))
           `(#:make-flags '("CFLAGS+=-maltivec"))
           '())
       #:phases
       (modify-phases %standard-phases
         (add-after 'install 'patch-suppression-files
           (lambda* (#:key outputs #:allow-other-keys)
             ;; Don't assume the FHS.
             (let* ((out (assoc-ref outputs "out"))
                    (dir (string-append out "/lib/valgrind")))
               (substitute* (find-files dir "\\.supp$")
                 (("obj:/lib") "obj:*/lib")
                 (("obj:/usr/X11R6/lib") "obj:*/lib")
                 (("obj:/usr/lib") "obj:*/lib"))
               #t)))
         (add-after 'install 'install-doc
           (lambda* (#:key outputs #:allow-other-keys)
             (let ((orig (format #f "~a/share/doc" (assoc-ref outputs "out")))
                   (dest (format #f "~a/share" (assoc-ref outputs "doc"))))
               (mkdir-p dest)
               (rename-file orig dest)
               #t))))))
    (native-inputs
     (list perl))
    (home-page "https://www.valgrind.org/")
    (synopsis "Debugging and profiling tool suite")
    (description
     "Valgrind is an instrumentation framework for building dynamic analysis
tools.  There are Valgrind tools that can automatically detect many memory
management and threading bugs, and profile your programs in detail.  You can
also use Valgrind to build new tools.")
    (license gpl2+)

    ;; Hide this variant so end users get the "interactive" Valgrind below.
    (properties '((hidden? . #t)))))

(define-public valgrind/interactive
  (package/inherit
   valgrind
   (inputs
    ;; GDB is needed to provide a sane default for `--db-command'.
    `(("gdb" ,gdb)))
   (properties '())))

(define-public valgrind-3.18
  (package
    (inherit valgrind/interactive)
    (version "3.18.1")
    (source (origin
              (method url-fetch)
              (uri (list (string-append "https://sourceware.org/pub/valgrind"
                                        "/valgrind-" version ".tar.bz2")
                         (string-append "ftp://sourceware.org/pub/valgrind"
                                        "/valgrind-" version ".tar.bz2")))
              (sha256
               (base32
                "1xgph509i6adv9w2glviw3xrmlz0dssg8992hbvxsbkp7ahrm180"))
              (patches (search-patches "valgrind-enable-arm.patch"))))))
