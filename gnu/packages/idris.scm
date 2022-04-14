;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2015 Paul van der Walt <paul@denknerd.org>
;;; Copyright © 2016, 2017 David Craven <david@craven.ch>
;;; Copyright © 2018 Alex ter Weele <alex.ter.weele@gmail.com>
;;; Copyright © 2019, 2021, 2022 Eric Bavier <bavier@posteo.net>
;;; Copyright © 2022 Attila Lendvai <attila@lendvai.name>
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

;;; TODO:
;;;
;;;  - Idris has multiple backends, but we only register Chez as an
;;;  input.  Decide how to make backends optional, and/or which ones to package
;;;  by default.
;;;
;;;  - Set RUNPATH instead of using LD_LIBRARY_PATH.  See
;;;  http://blog.tremily.us/posts/rpath/  This probably needs patching Idris
;;;  because it uses its FFI infrastrucutre to open libidris_support.so, which
;;;  is based on dlopen.
;;;
;;;  - The reason some of the historical packages point to
;;;  github.com/attila-lendvai-patches is that these versions need some
;;;  patches to make them buildable today, and these branches haven't been
;;;  incorporated into the official repo yet.  Once/if that happens, these
;;;  URL's can be changed to point to the official repo.

(define-module (gnu packages idris)
  #:use-module (gnu packages)
  #:use-module (gnu packages base)
  #:use-module (gnu packages bash)
  #:use-module (gnu packages chez)
  #:use-module (gnu packages haskell-check)
  #:use-module (gnu packages haskell-web)
  #:use-module (gnu packages haskell-xyz)
  #:use-module (gnu packages libffi)
  #:use-module (gnu packages multiprecision)
  #:use-module (gnu packages ncurses)
  #:use-module (gnu packages node)
  #:use-module (gnu packages perl)
  #:use-module (gnu packages python)
  #:use-module (gnu packages racket)
  #:use-module (gnu packages sphinx)
  #:use-module (gnu packages version-control)
  #:use-module (guix build-system gnu)
  #:use-module (guix build-system haskell)
  #:use-module (guix download)
  #:use-module (guix git)
  #:use-module (guix git-download)
  #:use-module (guix utils)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (guix gexp)
  #:use-module (guix packages)
  #:use-module (guix utils)
  #:use-module (ice-9 match)
  #:use-module (ice-9 regex)
  #:export (make-idris-package))

;;;
;;; Idris 1
;;;
(define-public idris-1.3
  (package
    (name "idris")
    (version "1.3.4")
    (source (origin
              (method git-fetch)
              (uri (git-reference
                    (url "https://github.com/idris-lang/Idris-dev.git")
                    (commit (string-append "v" version))))
              (file-name (git-file-name name version))
              (sha256
               (base32
                "0cd2a92323hb9a6wy8sc0cqwnisf4pv8y9y2rxvxcbyv8cs1q8g2"))
              (patches (search-patches "idris-test-ffi008.patch"))))
    (build-system haskell-build-system)
    (native-inputs                      ;For tests
     (list perl ghc-cheapskate ghc-tasty ghc-tasty-golden
           ghc-tasty-rerun))
    (inputs
     (list bash-minimal
           gmp
           ncurses
           ghc-aeson
           ghc-annotated-wl-pprint
           ghc-ansi-terminal
           ghc-ansi-wl-pprint
           ghc-async
           ghc-base64-bytestring
           ghc-blaze-html
           ghc-blaze-markup
           ghc-cheapskate
           ghc-code-page
           ghc-fingertree
           ghc-fsnotify
           ghc-ieee754
           ghc-libffi
           ghc-megaparsec
           ghc-network
           ghc-optparse-applicative
           ghc-regex-tdfa
           ghc-safe
           ghc-split
           ghc-terminal-size
           ghc-uniplate
           ghc-unordered-containers
           ghc-utf8-string
           ghc-vector
           ghc-vector-binary-instances
           ghc-zip-archive))
    (arguments
     `(#:configure-flags
       (list (string-append "--datasubdir="
                            (assoc-ref %outputs "out") "/lib/idris")
             "-fFFI" "-fGMP")
       #:phases
       (modify-phases %standard-phases
         ;; This allows us to call the 'idris' binary before installing.
         (add-after 'unpack 'set-ld-library-path
           (lambda _
             (setenv "LD_LIBRARY_PATH" (string-append (getcwd) "/dist/build"))))
         (add-before 'configure 'update-constraints
           (lambda _
             (substitute* "idris.cabal"
               (("(aeson|ansi-terminal|haskeline|megaparsec|optparse-applicative)\\s+[^,]+" all dep)
                dep))))
         (add-before 'configure 'set-cc-command
           (lambda _
             (setenv "CC" ,(cc-for-target))))
         (add-after 'install 'fix-libs-install-location
           (lambda* (#:key outputs #:allow-other-keys)
             (let* ((out (assoc-ref outputs "out"))
                    (lib (string-append out "/lib/idris"))
                    (modules (string-append lib "/libs")))
               (for-each
                (lambda (module)
                  (symlink (string-append modules "/" module)
                           (string-append lib "/" module)))
                '("prelude" "base" "contrib" "effects" "pruviloj")))))
         (delete 'check)                ;Run check later
         (add-after 'install 'check
           (lambda* (#:key outputs #:allow-other-keys #:rest args)
             (let ((out (assoc-ref outputs "out")))
               (chmod "test/scripts/timeout" #o755) ;must be executable
               (setenv "TASTY_NUM_THREADS" (number->string (parallel-job-count)))
               (setenv "IDRIS_CC" ,(cc-for-target)) ;Needed for creating executables
               (setenv "PATH" (string-append out "/bin:" (getenv "PATH")))
               (apply (assoc-ref %standard-phases 'check) args))))
         (add-before 'check 'restore-libidris_rts
           (lambda* (#:key outputs #:allow-other-keys)
             ;; The Haskell build system moves this library to the
             ;; "static" output.  Idris only knows how to find it in the
             ;; "out" output, so we restore it here.
             (let ((out (assoc-ref outputs "out"))
                   (static (assoc-ref outputs "static"))
                   (filename "/lib/idris/rts/libidris_rts.a"))
               (rename-file (string-append static filename)
                            (string-append out filename)))))
         (add-before 'check 'wrap-program
           (lambda* (#:key outputs inputs #:allow-other-keys)
             (let* ((out (assoc-ref outputs "out"))
                    (exe (string-append out "/bin/idris")))
               (wrap-program exe
                 `("IDRIS_CC" = (,',(cc-for-target))))
               (with-directory-excursion (string-append out "/bin/")
                 (let ((versioned-name ,(string-append name "-" version)))
                   (rename-file ,name versioned-name)
                   (symlink versioned-name ,name)))))))))
    (native-search-paths
     (list (search-path-specification
            (variable "IDRIS_LIBRARY_PATH")
            (files '("lib/idris")))))
    (home-page "https://www.idris-lang.org")
    (synopsis "General purpose language with full dependent types")
    (description "Idris is a general purpose language with full dependent
types.  It is compiled, with eager evaluation.  Dependent types allow types to
be predicated on values, meaning that some aspects of a program's behaviour
can be specified precisely in the type.  The language is closely related to
Epigram and Agda.")
    (license license:bsd-3)))

(define-public idris idris-1.3)

;;;
;;; Idris 2
;;;
(define* (make-idris-package source idris-version
                             #:key bootstrap-idris
                             (idris-version-tag #false)
                             (guix-version (string-append
                                            idris-version
                                            (if idris-version-tag
                                                (string-append
                                                 "-" idris-version-tag)
                                                "")))
                             (ignore-test-failures? #false)
                             (unwrap? #true)
                             (tests? #true)
                             (historical? #false)
                             (hidden? #false) ; or (hidden? historical?)
                             (substitutable? (not historical?))
                             (files-to-patch-for-shell
                              '("src/Compiler/Scheme/Chez.idr"
                                "src/Compiler/Scheme/Racket.idr"
                                "src/Compiler/Scheme/Gambit.idr"
                                "src/Compiler/ES/Node.idr"
                                "bootstrap/idris2_app/idris2.rkt"
                                "bootstrap/idris2_app/idris2.ss"
                                "build/stage1/idris2_app/idris2.ss"
                                "build/stage1/idris2_app/idris2.rkt"
                                ))
                             (with-bootstrap-shortcut? (not historical?)))
  "HISTORICAL? means that it's only interesting for historical reasons, e.g. to be
used as a bootsrapping stage.

WITH-BOOTSTRAP-SHORTCUT? controls whether to use a previous version of Idris to
build us (which is potentially recursive), or use the captured compiler output
(Scheme code)."
  (package
    (name "idris2")
    (version guix-version)
    (source (match source
              ((commit hash . url)
               (origin
                 (method git-fetch)
                 (uri (git-reference
                       (url (if (null? url)
                                "https://github.com/idris-lang/Idris2.git"
                                (car url)))
                       (commit commit)))
                 (sha256 (base32 hash))
                 (file-name (git-file-name name version))))
              ((or (? git-checkout?)
                   (? local-file?))
               source)))
    (build-system gnu-build-system)
    (native-inputs
     (list (if with-bootstrap-shortcut?
               chez-scheme
               bootstrap-idris)
           clang-toolchain-12 ; older clang-toolchain versions don't have a bin/cc
           coreutils which git
           sed
           ;; Only for the tests
           node
           racket
           ;; Only for the docs
           python-minimal
           python-sphinx
           python-sphinx-rtd-theme))
    (inputs
     (list bash-minimal chez-scheme gmp))
    (outputs '("out" "doc"))
    (arguments
     (list
      #:tests? tests?
      #:substitutable? substitutable?
      #:make-flags
      #~(list (string-append "CC=" #$(cc-for-target))
              #$(string-append "IDRIS_VERSION=" idris-version)
              #$(string-append "IDRIS_VERSION_TAG=" (or idris-version-tag ""))
              #$(if with-bootstrap-shortcut?
                    #~(string-append "SCHEME="
                                     #$(this-package-input "chez-scheme")
                                     "/bin/scheme")
                    #~(string-append "BOOTSTRAP_IDRIS="
                                     #$bootstrap-idris
                                     "/bin/" #$(package-name bootstrap-idris)))
              (string-append "PREFIX=" (assoc-ref %outputs "out"))
              "-j1")
      #:phases
      `(modify-phases %standard-phases
         (delete 'bootstrap)
         (delete 'configure)
         (delete 'check)    ; check must happen after install and wrap-program
         (add-before 'build 'build-doc
           (lambda* (#:key outputs #:allow-other-keys)
             (invoke "make" "--directory" "docs/" "html")))
         (add-after 'build-doc 'install-doc
           (lambda* (#:key outputs #:allow-other-keys)
             (let ((doc (assoc-ref outputs "doc")))
               (copy-recursively "docs/build/html"
                                 (string-append doc "/share/doc/"
                                                ,name "-" ,version)))))
         (add-after 'unpack 'patch-paths
           (lambda* (#:key inputs #:allow-other-keys)
             (let ((files-to-patch (filter file-exists?
                                           ',files-to-patch-for-shell)))
               (substitute* files-to-patch
                 ((,(regexp-quote "#!/bin/sh"))
                  (string-append "#!" (assoc-ref inputs "bash") "/bin/sh"))
                 (("/usr/bin/env")
                  (string-append (assoc-ref inputs "coreutils") "/bin/env"))))))
         ,@(if unwrap?
               `((add-after 'install 'unwrap
                   (lambda* (#:key outputs #:allow-other-keys)
                     ;; The bin/idris2 calls bin/idris2_app/idris2.so which is
                     ;; the real executable, but it sets LD_LIBRARY_PATH
                     ;; incorrectly.  Remove bin/idris2 and replace it with
                     ;; bin/idris2_app/idris2.so instead.
                     (let* ((out (assoc-ref outputs "out"))
                            (image-base (string-append
                                         out "/bin/idris2_app/idris2"))
                            (image (if (file-exists? image-base)
                                       image-base
                                       ;; For v0.5.1 and older.
                                       (string-append image-base ".so"))))
                       (delete-file (string-append out "/bin/idris2"))
                       (rename-file image (string-append out "/bin/idris2"))
                       (delete-file-recursively (string-append out "/bin/idris2_app"))
                       (delete-file-recursively (string-append out "/lib"))))))
               '())
         ,@(if with-bootstrap-shortcut?
               `((replace 'build
                   (lambda* (#:key make-flags #:allow-other-keys)
                     ;; i.e. do not build it using the previous version of
                     ;; Idris, but rather compile the comitted compiler
                     ;; output.
                     (apply invoke "make" "bootstrap" make-flags))))
               '())
         (add-after 'unwrap 'wrap-program
           (lambda* (#:key outputs inputs #:allow-other-keys)
             (let* ((chez (string-append (assoc-ref inputs "chez-scheme")
                                         "/bin/scheme"))
                    (out (assoc-ref outputs "out"))
                    (exe (string-append out "/bin/" ,name))
                    (version ,idris-version))
               (wrap-program exe
                 `("IDRIS2_PREFIX" = (,out))
                 `("LD_LIBRARY_PATH" prefix (,(string-append
                                               out "/idris2-" version "/lib")))
                 `("CC" = (,',(cc-for-target)))
                 `("CHEZ" = (,chez)))
               (with-directory-excursion (string-append out "/bin/")
                 (let ((versioned-name ,(string-append name "-" version)))
                   (rename-file ,name versioned-name)
                   (symlink versioned-name ,name))))))
         (add-after 'wrap-program 'check
           (lambda* (#:key outputs make-flags #:allow-other-keys)
             (let ((invoke-make
                    (lambda (target)
                      (apply invoke "make"
                             "INTERACTIVE="
                             ;; "THREADS=1" ; for reproducible test output
                             (string-append "IDRIS2="
                                            (assoc-ref outputs "out")
                                            "/bin/" ,name)
                             target make-flags))))
               ;; TODO This is something like how it should be handled, but
               ;; the Makefile unconditionally invokes the `testenv` target,
               ;; and thus overwrites the `runtest` script when `make test` is
               ;; invoked.  For now this situation is resolved in the Idris
               ;; Makefile, by explicitly invoking the Idris `runtest` wrapper
               ;; script with an sh prefix.
               ;;
               ;;(invoke-make "testenv")
               ;;(patch-shebang "build/stage2/runtests")
               (,(if ignore-test-failures?
                     'false-if-exception
                     'begin)
                (invoke-make "test"))))))))
    (properties `((hidden? . ,hidden?)))
    (home-page "https://www.idris-lang.org")
    (synopsis "General purpose language with full dependent types")
    (description "Idris is a general purpose language with full dependent
types.  It is compiled, with eager evaluation.  Dependent types allow types to
be predicated on values, meaning that some aspects of a program's behaviour
can be specified precisely in the type.  The language is closely related to
Epigram and Agda.")
    (license license:bsd-3)))

(define-public idris2-0.1.1
  ;; branch idris.2
  ;; This is the first (untagged) Idris2 version that bootstraps off of the
  ;; Idris1 line.  Originally it was in the repo called Idris2-boot.
  (make-idris-package '("3c2335ee6bc00b7f417ac672a4ab7b73599abeb3"
                        "10w10ggyvlw7m1pazbfxr4sj3wpb6z1ap6rg3lxc0z6f2s3x53cb")
                      "0.1.1"
                      #:bootstrap-idris idris-1.3
                      #:historical? #true
                      #:unwrap? #false
                      ;; TODO `make bootstrap` needs to be backported into the
                      ;; Makefile in this branch.  Force the bootstrap
                      ;; shortcut to be turned off.
                      #:with-bootstrap-shortcut? #false))

(define-public idris2-0.2.1
  ;; branch idris.3
  (make-idris-package '("257bbc27498808e8cd4155cc06ea3f6a07541537"
                        "0idxplcmd6p13i2n0g49bc2snddny4kdr4wvd8854snzsiwqn7p1"
                        "https://github.com/attila-lendvai-patches/Idris2")
                      "0.2.1"
                      #:bootstrap-idris idris2-0.1.1
                      #:historical? #true))

(define-public idris2-0.2.2
  ;; branch idris.4
  (make-idris-package '("9bc8e6e9834cbc7b52dc6ca2d80d7e96afeb47d1"
                        "0xzl1mb5yxgp6v36rngy00i59cfy67niyiblcpaksllrgmg639p4"
                        "https://github.com/attila-lendvai-patches/Idris2")
                      "0.2.2"
                      #:bootstrap-idris idris2-0.2.1
                      #:historical? #true))

(define-public idris2-0.3.0
  ;; branch idris.5
  (make-idris-package '("025b5cd25b76eae28283a10bd155c384e46fbd82"
                        "00a83paib571ahknipmgw7g9pbym105isk3bz0c1ng41s4kjpsxh"
                        "https://github.com/attila-lendvai-patches/Idris2")
                      "0.3.0"
                      #:bootstrap-idris idris2-0.2.2
                      #:historical? #true))

(define-public idris2-0.4.0
  ;; branch idris.6
  (make-idris-package '("v0.4.0"
                        "105jybjf5s0k6003qzfxchzsfcpsxip180bh3mdmi74d464d0h8g")
                      "0.4.0"
                      #:bootstrap-idris idris2-0.3.0
                      #:ignore-test-failures? #true ; TODO investigate
                      #:historical? #true))

(define-public idris2-0.5.1
  (make-idris-package '("v0.5.1"
                        "09k5fxnplp6fv3877ynz1lwq9zapxcxbvfvkn6g68yb0ivrff978")
                      "0.5.1"))

;; TODO re build failure: in the build sandbox some parts of the test output
;; is missing.  I cannot reproduce it in a guix shell.  My assumption is that
;; it's an Idris bug that only manifests in certain circumstances.  There are
;; some other issues left with the use of #!/bin/sh, too.
(define-public idris2-dev
  (make-idris-package '("4bb12225424d76c7874b176e2bfb8b5550c112eb"
                        "0kb800cgfm0afa83pbyi3x9bpswcl8jz4pr68zy092fs50km3bj7"
                        "https://github.com/attila-lendvai-patches/Idris2")
                      "0.5.1"
                      #:ignore-test-failures? #true
                      #:idris-version-tag "dev"))

(define-public idris2 idris2-0.5.1)

;;;
;;; Idris apps
;;;

;; Idris modules use the gnu-build-system so that the IDRIS_LIBRARY_PATH is set.
(define (idris-default-arguments name)
  `(#:modules ((guix build gnu-build-system)
               (guix build utils)
               (ice-9 ftw)
               (ice-9 match))
    #:phases
    (modify-phases %standard-phases
      (delete 'configure)
      (delete 'build)
      (delete 'check)
      (replace 'install
        (lambda* (#:key inputs outputs #:allow-other-keys)
          (let* ((out (assoc-ref outputs "out"))
                 (idris (assoc-ref inputs "idris"))
                 (idris-bin (string-append idris "/bin/idris"))
                 (idris-libs (string-append idris "/lib/idris/libs"))
                 (module-name (and (string-prefix? "idris-" ,name)
                                   (substring ,name 6)))
                 (ibcsubdir (string-append out "/lib/idris/" module-name))
                 (ipkg (string-append module-name ".ipkg"))
                 (idris-library-path (getenv "IDRIS_LIBRARY_PATH"))
                 (idris-path (string-split idris-library-path #\:))
                 (idris-path-files (apply append
                                          (map (lambda (path)
                                                 (map (lambda (dir)
                                                        (string-append path "/" dir))
                                                      (scandir path))) idris-path)))
                 (idris-path-subdirs (filter (lambda (path)
                                               (and path (match (stat:type (stat path))
                                                           ('directory #t)
                                                           (_ #f))))
                                                    idris-path-files))
                 (install-cmd (cons* idris-bin
                                     "--ibcsubdir" ibcsubdir
                                     "--build" ipkg
                                     ;; only trigger a build, as --ibcsubdir
                                     ;; already installs .ibc files.

                                     (apply append (map (lambda (path)
                                                          (list "--idrispath"
                                                                path))
                                                        idris-path-subdirs)))))
            ;; FIXME: Seems to be a bug in idris that causes a dubious failure.
            (apply system* install-cmd)))))))

(define-public idris-lightyear
  (let ((commit "6d65ad111b4bed2bc131396f8385528fc6b3678a"))
    (package
      (name "idris-lightyear")
      (version (git-version "0.1" "1" commit))
      (source (origin
                (method git-fetch)
                (uri (git-reference
                      (url "https://github.com/ziman/lightyear")
                      (commit commit)))
                (file-name (git-file-name name version))
                (sha256
                 (base32
                  "1pkxnn3ryr0v0cin4nasw7kgkc9dnnpja1nfbj466mf3qv5s98af"))))
      (build-system gnu-build-system)
      (native-inputs
       (list idris))
      (arguments (idris-default-arguments name))
      (home-page "https://github.com/ziman/lightyear")
      (synopsis "Lightweight parser combinator library for Idris")
      (description "Lightweight parser combinator library for Idris, inspired
by Parsec.  This package is used (almost) the same way as Parsec, except for one
difference: backtracking.")
      (license license:bsd-2))))

(define-public idris-wl-pprint
  (let ((commit "1d365fcf4ba075859844dbc5eb96a90f57b9f338"))
    (package
      (name "idris-wl-pprint")
      (version (git-version "0.1" "1" commit))
      (source (origin
                (method git-fetch)
                (uri (git-reference
                      (url "https://github.com/shayan-najd/wl-pprint")
                      (commit commit)))
                (file-name (git-file-name name version))
                (sha256
                 (base32
                  "0g7c3y9smifdz4sivi3qmvymhdr7v9kfq45fmfmmvkqcrix0spzn"))))
      (build-system gnu-build-system)
      (native-inputs
       (list idris))
      (arguments (idris-default-arguments name))
      (home-page "https://github.com/shayan-najd/wl-pprint")
      (synopsis "Pretty printing library")
      (description "A pretty printing library for Idris based on Phil Wadler's
paper A Prettier Printer and on Daan Leijen's extensions in the Haskell
wl-pprint library.")
      (license license:bsd-2))))

(define-public idris-bifunctors
  (let ((commit "53d06a6ccfe70c49c9ae8c8a4135981dd2173202"))
    (package
      (name "idris-bifunctors")
      (version (git-version "0.1" "1" commit))
      (source (origin
                (method git-fetch)
                (uri (git-reference
                      (url "https://github.com/HuwCampbell/Idris-Bifunctors")
                      (commit commit)))
                (file-name (string-append name "-" version "-checkout"))
                (sha256
                 (base32
                  "02vbsd3rmgnj0l1qq787709qcxjbr9890cbad4ykn27f77jk81h4"))))
      (build-system gnu-build-system)
      (native-inputs
       (list idris))
      (arguments (idris-default-arguments name))
      (home-page "https://github.com/HuwCampbell/Idris-Bifunctors")
      (synopsis "Bifunctor library")
      (description "This is a bifunctor library for Idris based off the
excellent Haskell Bifunctors package from Edward Kmett.")
      (license license:bsd-3))))

(define-public idris-lens
  (let ((commit "26f012005f6849806cea630afe317e42cae97f29"))
    (package
      (name "idris-lens")
      (version (git-version "0.1" "1" commit))
      (source (origin
                (method git-fetch)
                (uri (git-reference
                      (url "https://github.com/HuwCampbell/idris-lens")
                      (commit commit)))
                (file-name (git-file-name name version))
                (sha256
                 (base32
                  "06jzfj6rad08rk92w8jk5byi79svmyg0mrcqhibgx8rkjjy6vmai"))))
      (build-system gnu-build-system)
      (native-inputs
       (list idris))
      (propagated-inputs
       (list idris-bifunctors))
      (arguments (idris-default-arguments name))
      (home-page "https://github.com/HuwCampbell/idris-lens")
      (synopsis "Van Laarhoven lenses for Idris")
      (description "Lenses are composable functional references.  They allow
accessing and modifying data within a structure.")
      (license license:bsd-3))))
