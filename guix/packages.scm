;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2012, 2013, 2014, 2015, 2016, 2017, 2018, 2019, 2020 Ludovic Courtès <ludo@gnu.org>
;;; Copyright © 2014, 2015, 2017, 2018 Mark H Weaver <mhw@netris.org>
;;; Copyright © 2015 Eric Bavier <bavier@member.fsf.org>
;;; Copyright © 2016 Alex Kost <alezost@gmail.com>
;;; Copyright © 2017, 2019, 2020 Efraim Flashner <efraim@flashner.co.il>
;;; Copyright © 2019 Marius Bakke <mbakke@fastmail.com>
;;; Copyright © 2021 Chris Marusich <cmmarusich@gmail.com>
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

(define-module (guix packages)
  #:use-module (guix utils)
  #:use-module (guix records)
  #:use-module (guix store)
  #:use-module (guix monads)
  #:use-module (guix gexp)
  #:use-module (guix base32)
  #:autoload   (guix base64) (base64-decode)
  #:use-module (guix grafts)
  #:use-module (guix derivations)
  #:use-module (guix memoization)
  #:use-module (guix build-system)
  #:use-module (guix search-paths)
  #:use-module (guix sets)
  #:use-module (guix deprecation)
  #:use-module (guix i18n)
  #:use-module (ice-9 match)
  #:use-module (ice-9 vlist)
  #:use-module (ice-9 regex)
  #:use-module (srfi srfi-1)
  #:use-module (srfi srfi-9 gnu)
  #:use-module (srfi srfi-11)
  #:use-module (srfi srfi-26)
  #:use-module (srfi srfi-34)
  #:use-module (srfi srfi-35)
  #:use-module (rnrs bytevectors)
  #:use-module (web uri)
  #:re-export (%current-system
               %current-target-system
               search-path-specification)         ;for convenience
  #:export (content-hash
            content-hash?
            content-hash-algorithm
            content-hash-value

            origin
            origin?
            this-origin
            origin-uri
            origin-method
            origin-hash
            origin-sha256                         ;deprecated
            origin-file-name
            origin-actual-file-name
            origin-patches
            origin-patch-flags
            origin-patch-inputs
            origin-patch-guile
            origin-snippet
            origin-modules
            base32
            base64

            package
            package?
            this-package
            package-name
            package-upstream-name
            package-version
            package-full-name
            package-source
            package-build-system
            package-arguments
            package-inputs
            package-native-inputs
            package-propagated-inputs
            package-outputs
            package-native-search-paths
            package-search-paths
            package-replacement
            package-synopsis
            package-description
            package-license
            package-home-page
            package-supported-systems
            package-properties
            package-location
            hidden-package
            hidden-package?
            package-superseded
            deprecated-package
            package-field-location

            package-direct-sources
            package-transitive-sources
            package-direct-inputs
            package-transitive-inputs
            package-transitive-target-inputs
            package-transitive-native-inputs
            package-transitive-propagated-inputs
            package-transitive-native-search-paths
            package-transitive-supported-systems
            package-mapping
            package-input-rewriting
            package-input-rewriting/spec
            package-source-derivation
            package-derivation
            package-cross-derivation
            package-output
            package-grafts
            package-patched-vulnerabilities
            package-with-patches
            package-with-extra-patches
            package-with-c-toolchain
            package/inherit

            transitive-input-references

            %supported-systems
            %hurd-systems
            %cuirass-supported-systems
            supported-package?

            &package-error
            package-error?
            package-error-package
            &package-input-error
            package-input-error?
            package-error-invalid-input
            &package-cross-build-system-error
            package-cross-build-system-error?

            package->bag
            bag->derivation
            bag-direct-inputs
            bag-transitive-inputs
            bag-transitive-host-inputs
            bag-transitive-build-inputs
            bag-transitive-target-inputs
            package-closure

            default-guile
            default-guile-derivation
            set-guile-for-build
            package-file
            package->derivation
            package->cross-derivation
            origin->derivation))

;;; Commentary:
;;;
;;; This module provides a high-level mechanism to define packages in a
;;; Guix-based distribution.
;;;
;;; Code:

(define-syntax-rule (define-compile-time-decoder name string->bytevector)
  "Define NAME as a macro that runs STRING->BYTEVECTOR at macro expansion time
if possible."
  (define-syntax name
    (lambda (s)
      "Return the bytevector corresponding to the given textual
representation."
      (syntax-case s ()
        ((_ str)
         (string? (syntax->datum #'str))
         ;; A literal string: do the conversion at expansion time.
         (with-syntax ((bv (string->bytevector (syntax->datum #'str))))
           #''bv))
        ((_ str)
         #'(string->bytevector str))))))

(define-compile-time-decoder base32 nix-base32-string->bytevector)
(define-compile-time-decoder base64 base64-decode)

;; Crytographic content hash.
(define-immutable-record-type <content-hash>
  (%content-hash algorithm value)
  content-hash?
  (algorithm content-hash-algorithm)              ;symbol
  (value     content-hash-value))                 ;bytevector

(define-syntax-rule (define-content-hash-constructor name
                      (algorithm size) ...)
  "Define NAME as a <content-hash> constructor that ensures that (1) its
second argument is among the listed ALGORITHM, and (2), when possible, that
its first argument has the right size for the chosen algorithm."
  (define-syntax name
    (lambda (s)
      (syntax-case s (algorithm ...)
        ((_ bv algorithm)
         (let ((bv* (syntax->datum #'bv)))
           (when (and (bytevector? bv*)
                      (not (= size (bytevector-length bv*))))
             (syntax-violation 'content-hash "invalid content hash length" s))
           #'(%content-hash 'algorithm bv)))
        ...))))

(define-content-hash-constructor build-content-hash
  (sha256 32)
  (sha512 64)
  (sha3-256 32)
  (sha3-512 64)
  (blake2s-256 64))

(define-syntax content-hash
  (lambda (s)
    "Return a content hash with the given parameters.  The default hash
algorithm is sha256.  If the first argument is a literal string, it is decoded
as base32.  Otherwise, it must be a bytevector."
    ;; What we'd really want here is something like C++ 'constexpr'.
    (syntax-case s ()
      ((_ str)
       (string? (syntax->datum #'str))
       #'(content-hash str sha256))
      ((_ str algorithm)
       (string? (syntax->datum #'str))
       (with-syntax ((bv (base32 (syntax->datum #'str))))
         #'(content-hash bv algorithm)))
      ((_ (id str) algorithm)
       (and (string? (syntax->datum #'str))
            (free-identifier=? #'id #'base32))
       (with-syntax ((bv (nix-base32-string->bytevector (syntax->datum #'str))))
         #'(content-hash bv algorithm)))
      ((_ (id str) algorithm)
       (and (string? (syntax->datum #'str))
            (free-identifier=? #'id #'base64))
       (with-syntax ((bv (base64-decode (syntax->datum #'str))))
         #'(content-hash bv algorithm)))
      ((_ bv)
       #'(content-hash bv sha256))
      ((_ bv hash)
       #'(build-content-hash bv hash)))))

(define (print-content-hash hash port)
  (format port "#<content-hash ~a:~a>"
          (content-hash-algorithm hash)
          (and=> (content-hash-value hash)
                 bytevector->nix-base32-string)))

(set-record-type-printer! <content-hash> print-content-hash)


;; The source of a package, such as a tarball URL and fetcher---called
;; "origin" to avoid name clash with `package-source', `source', etc.
(define-record-type* <origin>
  %origin make-origin
  origin?
  this-origin
  (uri       origin-uri)                          ; string
  (method    origin-method)                       ; procedure
  (hash      origin-hash)                         ; <content-hash>
  (file-name origin-file-name (default #f))       ; optional file name

  ;; Patches are delayed so that the 'search-patch' calls are made lazily,
  ;; which reduces I/O on startup and allows patch-not-found errors to be
  ;; gracefully handled at run time.
  (patches   origin-patches                       ; list of file names
             (default '()) (delayed))

  (snippet   origin-snippet (default #f))         ; sexp or #f
  (patch-flags  origin-patch-flags                ; list of strings
                (default '("-p1")))

  ;; Patching requires Guile, GNU Patch, and a few more.  These two fields are
  ;; used to specify these dependencies when needed.
  (patch-inputs origin-patch-inputs               ; input list or #f
                (default #f))
  (modules      origin-modules                    ; list of module names
                (default '()))

  (patch-guile origin-patch-guile                 ; package or #f
               (default #f)))

(define-syntax origin-compatibility-helper
  (syntax-rules (sha256)
    ((_ () (fields ...))
     (%origin fields ...))
    ((_ ((sha256 exp) rest ...) (others ...))
     (%origin others ...
              (hash (content-hash exp sha256))
              rest ...))
    ((_ (field rest ...) (others ...))
     (origin-compatibility-helper (rest ...)
                                  (others ... field)))))

(define-syntax-rule (origin fields ...)
  "Build an <origin> record, automatically converting 'sha256' field
specifications to 'hash'."
  (origin-compatibility-helper (fields ...) ()))

(define-deprecated (origin-sha256 origin)
  origin-hash
  (let ((hash (origin-hash origin)))
    (unless (eq? (content-hash-algorithm hash) 'sha256)
      (raise (condition (&message
                         (message (G_ "no SHA256 hash for origin"))))))
    (content-hash-value hash)))

(define (print-origin origin port)
  "Write a concise representation of ORIGIN to PORT."
  (match origin
    (($ <origin> uri method hash file-name patches)
     (simple-format port "#<origin ~s ~a ~s ~a>"
                    uri hash
                    (force patches)
                    (number->string (object-address origin) 16)))))

(set-record-type-printer! <origin> print-origin)

(define (origin-actual-file-name origin)
  "Return the file name of ORIGIN, either its 'file-name' field or the file
name of its URI."
  (define (uri->file-name uri)
    ;; Return the 'base name' of URI or URI itself, where URI is a string.
    (let ((path (and=> (string->uri uri) uri-path)))
      (if path
          (basename path)
          uri)))

  (or (origin-file-name origin)
      (match (origin-uri origin)
        ((head . tail)
         (uri->file-name head))
        ((? string? uri)
         (uri->file-name uri))
        (else
         ;; git, svn, cvs, etc. reference
         #f))))


(define %supported-systems
  ;; This is the list of system types that are supported.  By default, we
  ;; expect all packages to build successfully here.
  '("x86_64-linux" "i686-linux" "armhf-linux" "aarch64-linux" "mips64el-linux" "i586-gnu"
    "powerpc64le-linux"))

(define %hurd-systems
  ;; The GNU/Hurd systems for which support is being developed.
  '("i586-gnu" "i686-gnu"))

(define %cuirass-supported-systems
  ;; This is the list of system types for which build machines are available.
  ;;
  ;; XXX: MIPS is unavailable in CI:
  ;; <https://lists.gnu.org/archive/html/guix-devel/2017-03/msg00790.html>.
  (fold delete %supported-systems '("mips64el-linux")))


;; A package.
(define-record-type* <package>
  package make-package
  package?
  this-package
  (name   package-name)                   ; string
  (version package-version)               ; string
  (source package-source)                 ; <origin> instance
  (build-system package-build-system)     ; build system
  (arguments package-arguments            ; arguments for the build method
             (default '()) (thunked))

  (inputs package-inputs                  ; input packages or derivations
          (default '()) (thunked))
  (propagated-inputs package-propagated-inputs    ; same, but propagated
                     (default '()) (thunked))
  (native-inputs package-native-inputs    ; native input packages/derivations
                 (default '()) (thunked))

  (outputs package-outputs                ; list of strings
           (default '("out")))

                                                  ; lists of
                                                  ; <search-path-specification>,
                                                  ; for native and cross
                                                  ; inputs
  (native-search-paths package-native-search-paths (default '()))
  (search-paths package-search-paths (default '()))

  ;; The 'replacement' field is marked as "innate" because it never makes
  ;; sense to inherit a replacement as is.  See the 'package/inherit' macro.
  (replacement package-replacement                ; package | #f
               (default #f) (thunked) (innate))

  (synopsis package-synopsis)                    ; one-line description
  (description package-description)              ; one or two paragraphs
  (license package-license)
  (home-page package-home-page)
  (supported-systems package-supported-systems    ; list of strings
                     (default %supported-systems))

  (properties package-properties (default '()))   ; alist for anything else

  (location package-location
            (default (and=> (current-source-location)
                            source-properties->location))
            (innate)))

(set-record-type-printer! <package>
                          (lambda (package port)
                            (let ((loc    (package-location package))
                                  (format simple-format))
                              (format port "#<package ~a@~a ~a~a>"
                                      (package-name package)
                                      (package-version package)
                                      (if loc
                                          (format #f "~a:~a "
                                                  (location-file loc)
                                                  (location-line loc))
                                          "")
                                      (number->string (object-address
                                                       package)
                                                      16)))))

(define-syntax-rule (package/inherit p overrides ...)
  "Like (package (inherit P) OVERRIDES ...), except that the same
transformation is done to the package P's replacement, if any.  P must be a bare
identifier, and will be bound to either P or its replacement when evaluating
OVERRIDES."
  (let loop ((p p))
    (package (inherit p)
      overrides ...
      (replacement (and=> (package-replacement p) loop)))))

(define (package-upstream-name package)
  "Return the upstream name of PACKAGE, which could be different from the name
it has in Guix."
  (or (assq-ref (package-properties package) 'upstream-name)
      (package-name package)))

(define (hidden-package p)
  "Return a \"hidden\" version of P--i.e., one that 'fold-packages' and thus,
user interfaces, ignores."
  (package
    (inherit p)
    (properties `((hidden? . #t)
                  ,@(package-properties p)))))

(define (hidden-package? p)
  "Return true if P is \"hidden\"--i.e., must not be visible to user
interfaces."
  (assoc-ref (package-properties p) 'hidden?))

(define (package-superseded p)
  "Return the package the supersedes P, or #f if P is still current."
  (assoc-ref (package-properties p) 'superseded))

(define (deprecated-package old-name p)
  "Return a package called OLD-NAME and marked as superseded by P, a package
object."
  (package
    (inherit p)
    (name old-name)
    (properties `((superseded . ,p)))))

(define (package-field-location package field)
  "Return the source code location of the definition of FIELD for PACKAGE, or
#f if it could not be determined."
  (define (goto port line column)
    (unless (and (= (port-column port) (- column 1))
                 (= (port-line port) (- line 1)))
      (unless (eof-object? (read-char port))
        (goto port line column))))

  (match (package-location package)
    (($ <location> file line column)
     (match (search-path %load-path file)
       ((? string? file-found)
        (catch 'system-error
          (lambda ()
            ;; In general we want to keep relative file names for modules.
            (call-with-input-file file-found
              (lambda (port)
                (goto port line column)
                (match (read port)
                  (('package inits ...)
                   (let ((field (assoc field inits)))
                     (match field
                       ((_ value)
                        (let ((loc (and=> (source-properties value)
                                          source-properties->location)))
                          (and loc
                               ;; Preserve the original file name, which may be a
                               ;; relative file name.
                               (set-field loc (location-file) file))))
                       (_
                        #f))))
                  (_
                   #f)))))
          (lambda _
            #f)))
       (#f
        ;; FILE could not be found in %LOAD-PATH.
        #f)))
    (_ #f)))


;; Error conditions.

(define-condition-type &package-error &error
  package-error?
  (package package-error-package))

(define-condition-type &package-input-error &package-error
  package-input-error?
  (input package-error-invalid-input))

(define-condition-type &package-cross-build-system-error &package-error
  package-cross-build-system-error?)

(define* (package-full-name package #:optional (delimiter "@"))
  "Return the full name of PACKAGE--i.e., `NAME@VERSION'.  By specifying
DELIMITER (a string), you can customize what will appear between the name and
the version.  By default, DELIMITER is \"@\"."
  (string-append (package-name package) delimiter (package-version package)))

(define (patch-file-name patch)
  "Return the basename of PATCH's file name, or #f if the file name could not
be determined."
  (match patch
    ((? string?)
     (basename patch))
    ((? origin?)
     (and=> (origin-actual-file-name patch) basename))))

(define %vulnerability-regexp
  ;; Regexp matching a CVE identifier in patch file names.
  (make-regexp "CVE-[0-9]{4}-[0-9]+"))

(define (package-patched-vulnerabilities package)
  "Return the list of patched vulnerabilities of PACKAGE as a list of CVE
identifiers.  The result is inferred from the file names of patches."
  (define (patch-vulnerabilities patch)
    (map (cut match:substring <> 0)
         (list-matches %vulnerability-regexp patch)))

  (let ((patches (filter-map patch-file-name
                             (or (and=> (package-source package)
                                        origin-patches)
                                 '()))))
    (append-map patch-vulnerabilities patches)))

(define (%standard-patch-inputs)
  (let* ((canonical (module-ref (resolve-interface '(gnu packages base))
                                'canonical-package))
         (ref       (lambda (module var)
                      (canonical
                       (module-ref (resolve-interface module) var)))))
    `(("tar"   ,(ref '(gnu packages base) 'tar))
      ("xz"    ,(ref '(gnu packages compression) 'xz))
      ("bzip2" ,(ref '(gnu packages compression) 'bzip2))
      ("gzip"  ,(ref '(gnu packages compression) 'gzip))
      ("lzip"  ,(ref '(gnu packages compression) 'lzip))
      ("unzip" ,(ref '(gnu packages compression) 'unzip))
      ("patch" ,(ref '(gnu packages base) 'patch))
      ("locales" ,(ref '(gnu packages base) 'glibc-utf8-locales)))))

(define (default-guile)
  "Return the default Guile package used to run the build code of
derivations."
  (let ((distro (resolve-interface '(gnu packages commencement))))
    (module-ref distro 'guile-final)))

(define (guile-for-grafts)
  "Return the Guile package used to build grafting derivations."
  ;; Guile 2.2 would not work due to <https://bugs.gnu.org/28211> when
  ;; grafting packages.
  (let ((distro (resolve-interface '(gnu packages guile))))
    (module-ref distro 'guile-2.0)))

(define* (default-guile-derivation #:optional (system (%current-system)))
  "Return the derivation for SYSTEM of the default Guile package used to run
the build code of derivation."
  (package->derivation (default-guile) system
                       #:graft? #f))

(define* (patch-and-repack source patches
                           #:key
                           inputs
                           (snippet #f)
                           (flags '("-p1"))
                           (modules '())
                           (guile-for-build (%guile-for-build))
                           (system (%current-system)))
  "Unpack SOURCE (a derivation or store path), apply all of PATCHES, and
repack the tarball using the tools listed in INPUTS.  When SNIPPET is true,
it must be an s-expression that will run from within the directory where
SOURCE was unpacked, after all of PATCHES have been applied.  MODULES
specifies modules in scope when evaluating SNIPPET."
  (define source-file-name
    ;; SOURCE is usually a derivation, but it could be a store file.
    (if (derivation? source)
        (derivation->output-path source)
        source))

  (define lookup-input
    ;; The default value of the 'patch-inputs' field, and thus INPUTS is #f,
    ;; so deal with that.
    (let ((inputs (or inputs (%standard-patch-inputs))))
      (lambda (name)
        (match (assoc-ref inputs name)
          ((package) package)
          (#f        #f)))))

  (define decompression-type
    (cond ((string-suffix? "gz" source-file-name)  "gzip")
          ((string-suffix? "Z" source-file-name)  "gzip")
          ((string-suffix? "bz2" source-file-name) "bzip2")
          ((string-suffix? "lz" source-file-name)  "lzip")
          ((string-suffix? "zip" source-file-name) "unzip")
          (else "xz")))

  (define original-file-name
    ;; Remove the store prefix plus the slash, hash, and hyphen.
    (let* ((sans (string-drop source-file-name
                              (+ (string-length (%store-prefix)) 1)))
           (dash (string-index sans #\-)))
      (string-drop sans (+ 1 dash))))

  (define (numeric-extension? file-name)
    ;; Return true if FILE-NAME ends with digits.
    (and=> (file-extension file-name)
           (cut string-every char-set:hex-digit <>)))

  (define (checkout? directory)
    ;; Return true if DIRECTORY is a checkout (git, svn, etc).
    (string-suffix? "-checkout" directory))

  (define (tarxz-name file-name)
    ;; Return a '.tar.xz' file name based on FILE-NAME.
    (let ((base (cond ((numeric-extension? file-name)
                       original-file-name)
                      ((checkout? file-name)
                       (string-drop-right file-name 9))
                      (else (file-sans-extension file-name)))))
      (string-append base
                     (if (equal? (file-extension base) "tar")
                         ".xz"
                         ".tar.xz"))))

  (define instantiate-patch
    (match-lambda
      ((? string? patch)                          ;deprecated
       (interned-file patch #:recursive? #t))
      ((? struct? patch)                          ;origin, local-file, etc.
       (lower-object patch system))))

  (mlet %store-monad ((tar ->     (lookup-input "tar"))
                      (xz ->      (lookup-input "xz"))
                      (patch ->   (lookup-input "patch"))
                      (locales -> (lookup-input "locales"))
                      (decomp ->  (lookup-input decompression-type))
                      (patches    (sequence %store-monad
                                            (map instantiate-patch patches))))
    (define build
      (with-imported-modules '((guix build utils))
        #~(begin
            (use-modules (ice-9 ftw)
                         (srfi srfi-1)
                         (guix build utils))

            ;; The --sort option was added to GNU tar in version 1.28, released
            ;; 2014-07-28.  During bootstrap we must cope with older versions.
            (define tar-supports-sort?
              (zero? (system* (string-append #+tar "/bin/tar")
                              "cf" "/dev/null" "--files-from=/dev/null"
                              "--sort=name")))

            (define (apply-patch patch)
              (format (current-error-port) "applying '~a'...~%" patch)

              ;; Use '--force' so that patches that do not apply perfectly are
              ;; rejected.  Use '--no-backup-if-mismatch' to prevent making
              ;; "*.orig" file if a patch is applied with offset.
              (invoke (string-append #+patch "/bin/patch")
                      "--force" "--no-backup-if-mismatch"
                      #+@flags "--input" patch))

            (define (first-file directory)
              ;; Return the name of the first file in DIRECTORY.
              (car (scandir directory
                            (lambda (name)
                              (not (member name '("." "..")))))))

            ;; Encoding/decoding errors shouldn't be silent.
            (fluid-set! %default-port-conversion-strategy 'error)

            (when #+locales
              ;; First of all, install a UTF-8 locale so that UTF-8 file names
              ;; are correctly interpreted.  During bootstrap, LOCALES is #f.
              (setenv "LOCPATH"
                      (string-append #+locales "/lib/locale/"
                                     #+(and locales
                                            (version-major+minor
                                             (package-version locales)))))
              (setlocale LC_ALL "en_US.utf8"))

            (setenv "PATH" (string-append #+xz "/bin" ":"
                                          #+decomp "/bin"))

            ;; SOURCE may be either a directory or a tarball.
            (if (file-is-directory? #+source)
                (let* ((store     (%store-directory))
                       (len       (+ 1 (string-length store)))
                       (base      (string-drop #+source len))
                       (dash      (string-index base #\-))
                       (directory (string-drop base (+ 1 dash))))
                  (mkdir directory)
                  (copy-recursively #+source directory))
                #+(if (string=? decompression-type "unzip")
                      #~(invoke "unzip" #+source)
                      #~(invoke (string-append #+tar "/bin/tar")
                                "xvf" #+source)))

            (let ((directory (first-file ".")))
              (format (current-error-port)
                      "source is under '~a'~%" directory)
              (chdir directory)

              (for-each apply-patch '#+patches)

              (let ((result #+(if snippet
                                  #~(let ((module (make-fresh-user-module)))
                                      (module-use-interfaces!
                                       module
                                       (map resolve-interface '#+modules))
                                      ((@ (system base compile) compile)
                                       '#+snippet
                                       #:to 'value
                                       #:opts %auto-compilation-options
                                       #:env module))
                                  #~#t)))
                ;; Issue a warning unless the result is #t.
                (unless (eqv? result #t)
                  (format (current-error-port) "\
## WARNING: the snippet returned `~s'.  Return values other than #t
## are deprecated.  Please migrate this package so that its snippet
## reports errors by raising an exception, and otherwise returns #t.~%"
                          result))
                (unless result
                  (error "snippet returned false")))

              (chdir "..")

              (unless tar-supports-sort?
                (call-with-output-file ".file_list"
                  (lambda (port)
                    (for-each (lambda (name)
                                (format port "~a~%" name))
                              (find-files directory
                                          #:directories? #t
                                          #:fail-on-error? #t)))))
              (apply invoke
                     (string-append #+tar "/bin/tar")
                     "cvfa" #$output
                     ;; Avoid non-determinism in the archive.  Set the mtime
                     ;; to 1 as is the case in the store (software like gzip
                     ;; behaves differently when it stumbles upon mtime = 0).
                     "--mtime=@1"
                     "--owner=root:0"
                     "--group=root:0"
                     (if tar-supports-sort?
                         `("--sort=name"
                           ,directory)
                         '("--no-recursion"
                           "--files-from=.file_list")))))))

    (let ((name (tarxz-name original-file-name)))
      (gexp->derivation name build
                        #:graft? #f
                        #:system system
                        #:guile-for-build guile-for-build
                        #:properties `((type . origin)
                                       (patches . ,(length patches)))))))

(define (package-with-patches original patches)
  "Return package ORIGINAL with PATCHES applied."
  (package (inherit original)
           (source (origin (inherit (package-source original))
                           (patches patches)))))

(define (package-with-extra-patches original patches)
  "Return package ORIGINAL with all PATCHES appended to its list of patches."
  (package-with-patches original
                        (append (origin-patches (package-source original))
                                patches)))

(define (package-with-c-toolchain package toolchain)
  "Return a variant of PACKAGE that uses TOOLCHAIN instead of the default GNU
C/C++ toolchain.  TOOLCHAIN must be a list of inputs (label/package tuples)
providing equivalent functionality, such as the 'gcc-toolchain' package."
  (let ((bs (package-build-system package)))
    (package/inherit package
      (build-system (build-system-with-c-toolchain bs toolchain)))))

(define (transitive-inputs inputs)
  "Return the closure of INPUTS when considering the 'propagated-inputs'
edges.  Omit duplicate inputs, except for those already present in INPUTS
itself.

This is implemented as a breadth-first traversal such that INPUTS is
preserved, and only duplicate propagated inputs are removed."
  (define (seen? seen item outputs)
    ;; FIXME: We're using pointer identity here, which is extremely sensitive
    ;; to memoization in package-producing procedures; see
    ;; <https://bugs.gnu.org/30155>.
    (match (vhash-assq item seen)
      ((_ . o) (equal? o outputs))
      (_       #f)))

  (let loop ((inputs     inputs)
             (result     '())
             (propagated '())
             (first?     #t)
             (seen       vlist-null))
    (match inputs
      (()
       (if (null? propagated)
           (reverse result)
           (loop (reverse (concatenate propagated)) result '() #f seen)))
      (((and input (label (? package? package) outputs ...)) rest ...)
       (if (and (not first?) (seen? seen package outputs))
           (loop rest result propagated first? seen)
           (loop rest
                 (cons input result)
                 (cons (package-propagated-inputs package) propagated)
                 first?
                 (vhash-consq package outputs seen))))
      ((input rest ...)
       (loop rest (cons input result) propagated first? seen)))))

(define (package-direct-sources package)
  "Return all source origins associated with PACKAGE; including origins in
PACKAGE's inputs."
  `(,@(or (and=> (package-source package) list) '())
    ,@(filter-map (match-lambda
                   ((_ (? origin? orig) _ ...)
                    orig)
                   (_ #f))
                  (package-direct-inputs package))))

(define (package-transitive-sources package)
  "Return PACKAGE's direct sources, and their direct sources, recursively."
  (delete-duplicates
   (concatenate (filter-map (match-lambda
                             ((_ (? origin? orig) _ ...)
                              (list orig))
                             ((_ (? package? p) _ ...)
                              (package-direct-sources p))
                             (_ #f))
                            (bag-transitive-inputs
                             (package->bag package))))))

(define (package-direct-inputs package)
  "Return all the direct inputs of PACKAGE---i.e, its direct inputs along
with their propagated inputs."
  (append (package-native-inputs package)
          (package-inputs package)
          (package-propagated-inputs package)))

(define (package-transitive-inputs package)
  "Return the transitive inputs of PACKAGE---i.e., its direct inputs along
with their propagated inputs, recursively."
  (transitive-inputs (package-direct-inputs package)))

(define (package-transitive-target-inputs package)
  "Return the transitive target inputs of PACKAGE---i.e., its direct inputs
along with their propagated inputs, recursively.  This only includes inputs
for the target system, and not native inputs."
  (transitive-inputs (append (package-inputs package)
                             (package-propagated-inputs package))))

(define (package-transitive-native-inputs package)
  "Return the transitive native inputs of PACKAGE---i.e., its direct inputs
along with their propagated inputs, recursively.  This only includes inputs
for the host system (\"native inputs\"), and not target inputs."
  (transitive-inputs (package-native-inputs package)))

(define (package-transitive-propagated-inputs package)
  "Return the propagated inputs of PACKAGE, and their propagated inputs,
recursively."
  (transitive-inputs (package-propagated-inputs package)))

(define (package-transitive-native-search-paths package)
  "Return the list of search paths for PACKAGE and its propagated inputs,
recursively."
  (append (package-native-search-paths package)
          (append-map (match-lambda
                        ((label (? package? p) _ ...)
                         (package-native-search-paths p))
                        (_
                         '()))
                      (package-transitive-propagated-inputs package))))

(define (transitive-input-references alist inputs)
  "Return a list of (assoc-ref ALIST <label>) for each (<label> <package> . _)
in INPUTS and their transitive propagated inputs."
  (define label
    (match-lambda
      ((label . _)
       label)))

  (map (lambda (input)
         `(assoc-ref ,alist ,(label input)))
       (transitive-inputs inputs)))

(define package-transitive-supported-systems
  (let ()
    (define supported-systems
      (mlambda (package system)
        (parameterize ((%current-system system))
          (fold (lambda (input systems)
                  (match input
                    ((label (? package? package) . _)
                     (lset-intersection string=? systems
                                        (supported-systems package system)))
                    (_
                     systems)))
                (package-supported-systems package)
                (bag-direct-inputs (package->bag package))))))

    (lambda* (package #:optional (system (%current-system)))
      "Return the intersection of the systems supported by PACKAGE and those
supported by its dependencies."
      (supported-systems package system))))

(define* (supported-package? package #:optional (system (%current-system)))
  "Return true if PACKAGE is supported on SYSTEM--i.e., if PACKAGE and all its
dependencies are known to build on SYSTEM."
  (member system (package-transitive-supported-systems package system)))

(define (bag-direct-inputs bag)
  "Same as 'package-direct-inputs', but applied to a bag."
  (append (bag-build-inputs bag)
          (bag-host-inputs bag)
          (bag-target-inputs bag)))

(define (bag-transitive-inputs bag)
  "Same as 'package-transitive-inputs', but applied to a bag."
  (parameterize ((%current-target-system #f)
                 (%current-system (bag-system bag)))
    (transitive-inputs (bag-direct-inputs bag))))

(define (bag-transitive-build-inputs bag)
  "Same as 'package-transitive-native-inputs', but applied to a bag."
  (parameterize ((%current-target-system #f)
                 (%current-system (bag-system bag)))
    (transitive-inputs (bag-build-inputs bag))))

(define (bag-transitive-host-inputs bag)
  "Same as 'package-transitive-target-inputs', but applied to a bag."
  (parameterize ((%current-target-system (bag-target bag))
                 (%current-system (bag-system bag)))
    (transitive-inputs (bag-host-inputs bag))))

(define (bag-transitive-target-inputs bag)
  "Return the \"target inputs\" of BAG, recursively."
  (parameterize ((%current-target-system (bag-target bag))
                 (%current-system (bag-system bag)))
    (transitive-inputs (bag-target-inputs bag))))

(define* (package-closure packages #:key (system (%current-system)))
  "Return the closure of PACKAGES on SYSTEM--i.e., PACKAGES and the list of
packages they depend on, recursively."
  (let loop ((packages packages)
             (visited  vlist-null)
             (closure  (list->setq packages)))
    (match packages
      (()
       (set->list closure))
      ((package . rest)
       (if (vhash-assq package visited)
           (loop rest visited closure)
           (let* ((bag          (package->bag package system))
                  (dependencies (filter-map (match-lambda
                                              ((label (? package? package) . _)
                                               package)
                                              (_ #f))
                                            (bag-direct-inputs bag))))
             (loop (append dependencies rest)
                   (vhash-consq package #t visited)
                   (fold set-insert closure dependencies))))))))

(define (build-system-with-package-mapping bs rewrite)
  "Return a variant of BS, a build system, that rewrites a bag's inputs by
passing them through REWRITE, a procedure that takes an input tuplet and
returns a \"rewritten\" input tuplet."
  (define lower
    (build-system-lower bs))

  (define (lower* . args)
    (let ((lowered (apply lower args)))
      (bag
        (inherit lowered)
        (build-inputs (map rewrite (bag-build-inputs lowered)))
        (host-inputs (map rewrite (bag-host-inputs lowered)))
        (target-inputs (map rewrite (bag-target-inputs lowered))))))

  (build-system
    (inherit bs)
    (lower lower*)))

(define* (package-mapping proc #:optional (cut? (const #f))
                          #:key deep?)
  "Return a procedure that, given a package, applies PROC to all the packages
depended on and returns the resulting package.  The procedure stops recursion
when CUT? returns true for a given package.  When DEEP? is true, PROC is
applied to implicit inputs as well."
  (define (rewrite input)
    (match input
      ((label (? package? package) outputs ...)
       (cons* label (replace package) outputs))
      (_
       input)))

  (define mapping-property
    ;; Property indicating whether the package has already been processed.
    (gensym " package-mapping-done"))

  (define replace
    (mlambdaq (p)
      ;; If P is the result of a previous call, return it.
      (cond ((assq-ref (package-properties p) mapping-property)
             p)

            ((cut? p)
             ;; Since P's propagated inputs are really inputs of its dependents,
             ;; rewrite them as well, unless we're doing a "shallow" rewrite.
             (let ((p (proc p)))
               (if (or (not deep?)
                       (null? (package-propagated-inputs p)))
                   p
                   (package
                     (inherit p)
                     (location (package-location p))
                     (replacement (package-replacement p))
                     (propagated-inputs (map rewrite (package-propagated-inputs p)))
                     (properties `((,mapping-property . #t)
                                   ,@(package-properties p)))))))

            (else
             ;; Return a variant of P with PROC applied to P and its explicit
             ;; dependencies, recursively.  Memoize the transformations.  Failing
             ;; to do that, we would build a huge object graph with lots of
             ;; duplicates, which in turns prevents us from benefiting from
             ;; memoization in 'package-derivation'.
             (let ((p (proc p)))
               (package
                 (inherit p)
                 (location (package-location p))
                 (build-system (if deep?
                                   (build-system-with-package-mapping
                                    (package-build-system p) rewrite)
                                   (package-build-system p)))
                 (inputs (map rewrite (package-inputs p)))
                 (native-inputs (map rewrite (package-native-inputs p)))
                 (propagated-inputs (map rewrite (package-propagated-inputs p)))
                 (replacement (and=> (package-replacement p) replace))
                 (properties `((,mapping-property . #t)
                               ,@(package-properties p)))))))))

  replace)

(define* (package-input-rewriting replacements
                                  #:optional (rewrite-name identity)
                                  #:key (deep? #t))
  "Return a procedure that, when passed a package, replaces its direct and
indirect dependencies, including implicit inputs when DEEP? is true, according
to REPLACEMENTS.  REPLACEMENTS is a list of package pairs; the first element
of each pair is the package to replace, and the second one is the replacement.

Optionally, REWRITE-NAME is a one-argument procedure that takes the name of a
package and returns its new name after rewrite."
  (define replacement-property
    ;; Property to tag right-hand sides in REPLACEMENTS.
    (gensym " package-replacement"))

  (define (rewrite p)
    (if (assq-ref (package-properties p) replacement-property)
        p
        (match (assq-ref replacements p)
          (#f  (package/inherit p
                 (name (rewrite-name (package-name p)))))
          (new (if deep?
                   (package/inherit new
                     (properties `((,replacement-property . #t)
                                   ,@(package-properties new))))
                   new)))))

  (define (cut? p)
    (or (assq-ref (package-properties p) replacement-property)
        (assq-ref replacements p)))

  (package-mapping rewrite cut?
                   #:deep? deep?))

(define* (package-input-rewriting/spec replacements #:key (deep? #t))
  "Return a procedure that, given a package, applies the given REPLACEMENTS to
all the package graph, including implicit inputs unless DEEP? is false.
REPLACEMENTS is a list of spec/procedures pair; each spec is a package
specification such as \"gcc\" or \"guile@2\", and each procedure takes a
matching package and returns a replacement for that package."
  (define table
    (fold (lambda (replacement table)
            (match replacement
              ((spec . proc)
               (let-values (((name version)
                             (package-name->name+version spec)))
                 (vhash-cons name (list version proc) table)))))
          vlist-null
          replacements))

  (define (find-replacement package)
    (vhash-fold* (lambda (item proc)
                   (or proc
                       (match item
                         ((#f proc)
                          proc)
                         ((version proc)
                          (and (version-prefix? version
                                                (package-version package))
                               proc)))))
                 #f
                 (package-name package)
                 table))

  (define replacement-property
    (gensym " package-replacement"))

  (define (rewrite p)
    (if (assq-ref (package-properties p) replacement-property)
        p
        (match (find-replacement p)
          (#f p)
          (proc
           (let ((new (proc p)))
             ;; Mark NEW as already processed.
             (package/inherit new
               (properties `((,replacement-property . #t)
                             ,@(package-properties new)))))))))

  (define (cut? p)
    (or (assq-ref (package-properties p) replacement-property)
        (find-replacement p)))

  (package-mapping rewrite cut?
                   #:deep? deep?))


;;;
;;; Package derivations.
;;;

(define %derivation-cache
  ;; Package to derivation-path mapping.
  (make-weak-key-hash-table 100))

(define (cache! cache package system thunk)
  "Memoize in CACHE the return values of THUNK as the derivation of PACKAGE on
SYSTEM."
  ;; FIXME: This memoization should be associated with the open store, because
  ;; otherwise it breaks when switching to a different store.
  (let ((result (thunk)))
    ;; Use `hashq-set!' instead of `hash-set!' because `hash' returns the
    ;; same value for all structs (as of Guile 2.0.6), and because pointer
    ;; equality is sufficient in practice.
    (hashq-set! cache package
                `((,system . ,result)
                  ,@(or (hashq-ref cache package) '())))
    result))

(define-syntax cached
  (syntax-rules (=>)
    "Memoize the result of BODY for the arguments PACKAGE and SYSTEM.
Return the cached result when available."
    ((_ (=> cache) package system body ...)
     (let ((thunk (lambda () body ...))
           (key   system))
       (match (hashq-ref cache package)
         ((alist (... ...))
          (match (assoc-ref alist key)
            (#f (cache! cache package key thunk))
            (value value)))
         (#f
          (cache! cache package key thunk)))))
    ((_ package system body ...)
     (cached (=> %derivation-cache) package system body ...))))

(define* (expand-input store package input system #:optional cross-system)
  "Expand INPUT, an input tuple, such that it contains only references to
derivation paths or store paths.  PACKAGE is only used to provide contextual
information in exceptions."
  (define (intern file)
    ;; Add FILE to the store.  Set the `recursive?' bit to #t, so that
    ;; file permissions are preserved.
    (add-to-store store (basename file) #t "sha256" file))

  (define derivation
    (if cross-system
        (cut package-cross-derivation store <> cross-system system
             #:graft? #f)
        (cut package-derivation store <> system #:graft? #f)))

  (match input
    (((? string? name) (? package? package))
     (list name (derivation package)))
    (((? string? name) (? package? package)
      (? string? sub-drv))
     (list name (derivation package)
           sub-drv))
    (((? string? name)
      (and (? string?) (? derivation-path?) drv))
     (list name drv))
    (((? string? name)
      (and (? string?) (? file-exists? file)))
     ;; Add FILE to the store.  When FILE is in the sub-directory of a
     ;; store path, it needs to be added anyway, so it can be used as a
     ;; source.
     (list name (intern file)))
    (((? string? name) (? struct? source))
     ;; 'package-source-derivation' calls 'lower-object', which can throw
     ;; '&gexp-input-error'.  However '&gexp-input-error' lacks source
     ;; location info, so we catch and rethrow here (XXX: not optimal
     ;; performance-wise).
     (guard (c ((gexp-input-error? c)
                (raise (condition
                        (&package-input-error
                         (package package)
                         (input   (gexp-error-invalid-input c)))))))
       (list name (package-source-derivation store source system))))
    (x
     (raise (condition (&package-input-error
                        (package package)
                        (input   x)))))))

(define %bag-cache
  ;; 'eq?' cache mapping packages to system+target+graft?-dependent bags.
  ;; It significantly speeds things up when doing repeated calls to
  ;; 'package->bag' as is the case when building a profile.
  (make-weak-key-hash-table 200))

(define* (package->bag package #:optional
                       (system (%current-system))
                       (target (%current-target-system))
                       #:key (graft? (%graft?)))
  "Compile PACKAGE into a bag for SYSTEM, possibly cross-compiled to TARGET,
and return it."
  (let ((package (or (and graft? (package-replacement package))
                     package)))
    (cached (=> %bag-cache)
            package (list system target)
            ;; Bind %CURRENT-SYSTEM and %CURRENT-TARGET-SYSTEM so that thunked
            ;; field values can refer to it.
            (parameterize ((%current-system system)
                           (%current-target-system target))
              (match package
                ((and self
                      ($ <package> name version source build-system
                                   args inputs propagated-inputs native-inputs
                                   outputs))
                 ;; Even though we prefer to use "@" to separate the package
                 ;; name from the package version in various user-facing parts
                 ;; of Guix, checkStoreName (in nix/libstore/store-api.cc)
                 ;; prohibits the use of "@", so use "-" instead.
                 (or (make-bag build-system (string-append name "-" version)
                               #:system system
                               #:target target
                               #:source source
                               #:inputs (append (inputs self)
                                                (propagated-inputs self))
                               #:outputs outputs
                               #:native-inputs (native-inputs self)
                               #:arguments (args self))
                     (raise (if target
                                (condition
                                 (&package-cross-build-system-error
                                  (package package)))
                                (condition
                                 (&package-error
                                  (package package))))))))))))

(define %graft-cache
  ;; 'eq?' cache mapping package objects to a graft corresponding to their
  ;; replacement package.
  (make-weak-key-hash-table 200))

(define (input-graft store system)
  "Return a procedure that, given a package with a replacement and an output name,
returns a graft, and #f otherwise."
  (match-lambda*
    (((? package? package) output)
     (let ((replacement (package-replacement package)))
       (and replacement
            (cached (=> %graft-cache) package (cons output system)
                    (let ((orig (package-derivation store package system
                                                    #:graft? #f))
                          (new  (package-derivation store replacement system
                                                    #:graft? #t)))
                      (graft
                        (origin orig)
                        (origin-output output)
                        (replacement new)
                        (replacement-output output)))))))))

(define (input-cross-graft store target system)
  "Same as 'input-graft', but for cross-compilation inputs."
  (match-lambda*
    (((? package? package) output)
     (let ((replacement (package-replacement package)))
       (and replacement
            (let ((orig (package-cross-derivation store package target system
                                                  #:graft? #f))
                  (new  (package-cross-derivation store replacement
                                                  target system
                                                  #:graft? #t)))
              (graft
                (origin orig)
                (origin-output output)
                (replacement new)
                (replacement-output output))))))))

(define* (fold-bag-dependencies proc seed bag
                                #:key (native? #t))
  "Fold PROC over the packages BAG depends on.  Each package is visited only
once, in depth-first order.  If NATIVE? is true, restrict to native
dependencies; otherwise, restrict to target dependencies."
  (define bag-direct-inputs*
    (if native?
        (lambda (bag)
          (append (bag-build-inputs bag)
                  (bag-target-inputs bag)
                  (if (bag-target bag)
                      '()
                      (bag-host-inputs bag))))
        bag-host-inputs))

  (let loop ((inputs (bag-direct-inputs* bag))
             (result seed)
             (visited vlist-null))
    (match inputs
      (()
       result)
      (((label (? package? head) . rest) . tail)
       (let ((output  (match rest (() "out") ((output) output)))
             (outputs (vhash-foldq* cons '() head visited)))
         (if (member output outputs)
             (loop tail result visited)
             (let ((inputs (bag-direct-inputs* (package->bag head))))
               (loop (append inputs tail)
                     (proc head output result)
                     (vhash-consq head output visited))))))
      ((head . tail)
       (loop tail result visited)))))

(define* (bag-grafts store bag)
  "Return the list of grafts potentially applicable to BAG.  Potentially
applicable grafts are collected by looking at direct or indirect dependencies
of BAG that have a 'replacement'.  Whether a graft is actually applicable
depends on whether the outputs of BAG depend on the items the grafts refer
to (see 'graft-derivation'.)"
  (define system (bag-system bag))
  (define target (bag-target bag))

  (define native-grafts
    (let ((->graft (input-graft store system)))
      (parameterize ((%current-system system)
                     (%current-target-system #f))
        (fold-bag-dependencies (lambda (package output grafts)
                                 (match (->graft package output)
                                   (#f    grafts)
                                   (graft (cons graft grafts))))
                               '()
                               bag))))

  (define target-grafts
    (if target
        (let ((->graft (input-cross-graft store target system)))
          (parameterize ((%current-system system)
                         (%current-target-system target))
            (fold-bag-dependencies (lambda (package output grafts)
                                     (match (->graft package output)
                                       (#f    grafts)
                                       (graft (cons graft grafts))))
                                   '()
                                   bag
                                   #:native? #f)))
        '()))

  ;; We can end up with several identical grafts if we stumble upon packages
  ;; that are not 'eq?' but map to the same derivation (this can happen when
  ;; using things like 'package-with-explicit-inputs'.)  Hence the
  ;; 'delete-duplicates' call.
  (delete-duplicates
   (append native-grafts target-grafts)))

(define* (package-grafts store package
                         #:optional (system (%current-system))
                         #:key target)
  "Return the list of grafts applicable to PACKAGE as built for SYSTEM and
TARGET."
  (let* ((package (or (package-replacement package) package))
         (bag     (package->bag package system target)))
    (bag-grafts store bag)))

(define* (bag->derivation store bag
                          #:optional context)
  "Return the derivation to build BAG for SYSTEM.  Optionally, CONTEXT can be
a package object describing the context in which the call occurs, for improved
error reporting."
  (if (bag-target bag)
      (bag->cross-derivation store bag)
      (let* ((system     (bag-system bag))
             (inputs     (bag-transitive-inputs bag))
             (input-drvs (map (cut expand-input store context <> system)
                              inputs))
             (paths      (delete-duplicates
                          (append-map (match-lambda
                                       ((_ (? package? p) _ ...)
                                        (package-native-search-paths
                                         p))
                                       (_ '()))
                                      inputs))))

        (apply (bag-build bag)
               store (bag-name bag) input-drvs
               #:search-paths paths
               #:outputs (bag-outputs bag) #:system system
               (bag-arguments bag)))))

(define* (bag->cross-derivation store bag
                                #:optional context)
  "Return the derivation to build BAG, which is actually a cross build.
Optionally, CONTEXT can be a package object denoting the context of the call.
This is an internal procedure."
  (let* ((system      (bag-system bag))
         (target      (bag-target bag))
         (host        (bag-transitive-host-inputs bag))
         (host-drvs   (map (cut expand-input store context <> system target)
                           host))
         (target*     (bag-transitive-target-inputs bag))
         (target-drvs (map (cut expand-input store context <> system)
                           target*))
         (build       (bag-transitive-build-inputs bag))
         (build-drvs  (map (cut expand-input store context <> system)
                           build))
         (all         (append build target* host))
         (paths       (delete-duplicates
                       (append-map (match-lambda
                                    ((_ (? package? p) _ ...)
                                     (package-search-paths p))
                                    (_ '()))
                                   all)))
         (npaths      (delete-duplicates
                       (append-map (match-lambda
                                    ((_ (? package? p) _ ...)
                                     (package-native-search-paths
                                      p))
                                    (_ '()))
                                   all))))

    (apply (bag-build bag)
           store (bag-name bag)
           #:native-drvs build-drvs
           #:target-drvs (append host-drvs target-drvs)
           #:search-paths paths
           #:native-search-paths npaths
           #:outputs (bag-outputs bag)
           #:system system #:target target
           (bag-arguments bag))))

(define* (package-derivation store package
                             #:optional (system (%current-system))
                             #:key (graft? (%graft?)))
  "Return the <derivation> object of PACKAGE for SYSTEM."

  ;; Compute the derivation and cache the result.  Caching is important
  ;; because some derivations, such as the implicit inputs of the GNU build
  ;; system, will be queried many, many times in a row.
  (cached package (cons system graft?)
          (let* ((bag (package->bag package system #f #:graft? graft?))
                 (drv (bag->derivation store bag package)))
            (if graft?
                (match (bag-grafts store bag)
                  (()
                   drv)
                  (grafts
                   (let ((guile (package-derivation store (guile-for-grafts)
                                                    system #:graft? #f)))
                     ;; TODO: As an optimization, we can simply graft the tip
                     ;; of the derivation graph since 'graft-derivation'
                     ;; recurses anyway.
                     (graft-derivation store drv grafts
                                       #:system system
                                       #:guile guile))))
                drv))))

(define* (package-cross-derivation store package target
                                   #:optional (system (%current-system))
                                   #:key (graft? (%graft?)))
  "Cross-build PACKAGE for TARGET (a GNU triplet) from host SYSTEM (a Guix
system identifying string)."
  (cached package (list system target graft?)
          (let* ((bag (package->bag package system target #:graft? graft?))
                 (drv (bag->derivation store bag package)))
            (if graft?
                (match (bag-grafts store bag)
                  (()
                   drv)
                  (grafts
                   (graft-derivation store drv grafts
                                     #:system system
                                     #:guile
                                     (package-derivation store (guile-for-grafts)
                                                         system #:graft? #f))))
                drv))))

(define* (package-output store package
                         #:optional (output "out") (system (%current-system)))
  "Return the output path of PACKAGE's OUTPUT for SYSTEM---where OUTPUT is the
symbolic output name, such as \"out\".  Note that this procedure calls
`package-derivation', which is costly."
  (let ((drv (package-derivation store package system)))
    (derivation->output-path drv output)))


;;;
;;; Monadic interface.
;;;

(define (set-guile-for-build guile)
  "This monadic procedure changes the Guile currently used to run the build
code of derivations to GUILE, a package object."
  (lambda (store)
    (let ((guile (package-derivation store guile)))
      (values (%guile-for-build guile) store))))

(define* (package-file package
                       #:optional file
                       #:key
                       system (output "out") target)
  "Return as a monadic value the absolute file name of FILE within the
OUTPUT directory of PACKAGE.  When FILE is omitted, return the name of the
OUTPUT directory of PACKAGE.  When TARGET is true, use it as a
cross-compilation target triplet.

Note that this procedure does _not_ build PACKAGE.  Thus, the result might or
might not designate an existing file.  We recommend not using this procedure
unless you know what you are doing."
  (lambda (store)
    (define compute-derivation
      (if target
          (cut package-cross-derivation <> <> target <>)
          package-derivation))

    (let* ((system (or system (%current-system)))
           (drv    (compute-derivation store package system))
           (out    (derivation->output-path drv output)))
      (values (if file
                  (string-append out "/" file)
                  out)
              store))))

(define package->derivation
  (store-lift package-derivation))

(define package->cross-derivation
  (store-lift package-cross-derivation))

(define-gexp-compiler (package-compiler (package <package>) system target)
  ;; Compile PACKAGE to a derivation for SYSTEM, optionally cross-compiled for
  ;; TARGET.  This is used when referring to a package from within a gexp.
  (if target
      (package->cross-derivation package target system)
      (package->derivation package system)))

(define* (origin->derivation origin
                             #:optional (system (%current-system)))
  "Return the derivation corresponding to ORIGIN."
  (match origin
    (($ <origin> uri method hash name (= force ()) #f)
     ;; No patches, no snippet: this is a fixed-output derivation.
     (method uri
             (content-hash-algorithm hash)
             (content-hash-value hash)
             name #:system system))
    (($ <origin> uri method hash name (= force (patches ...)) snippet
        (flags ...) inputs (modules ...) guile-for-build)
     ;; Patches and/or a snippet.
     (mlet %store-monad ((source (method uri
                                         (content-hash-algorithm hash)
                                         (content-hash-value hash)
                                         name #:system system))
                         (guile  (package->derivation (or guile-for-build
                                                          (default-guile))
                                                      system
                                                      #:graft? #f)))
       (patch-and-repack source patches
                         #:inputs inputs
                         #:snippet snippet
                         #:flags flags
                         #:system system
                         #:modules modules
                         #:guile-for-build guile)))))

(define-gexp-compiler (origin-compiler (origin <origin>) system target)
  ;; Compile ORIGIN to a derivation for SYSTEM.  This is used when referring
  ;; to an origin from within a gexp.
  (origin->derivation origin system))

(define package-source-derivation                 ;somewhat deprecated
  (let ((lower (store-lower lower-object)))
    (lambda* (store source #:optional (system (%current-system)))
      "Return the derivation or file corresponding to SOURCE, which can be an
a file name or any object handled by 'lower-object', such as an <origin>.
When SOURCE is a file name, return either the interned file name (if SOURCE is
outside of the store) or SOURCE itself (if SOURCE is already a store item.)"
      (match source
        ((and (? string?) (? direct-store-path?) file)
         file)
        ((? string? file)
         (add-to-store store (basename file) #t "sha256" file))
        (_
         (lower store source system))))))
