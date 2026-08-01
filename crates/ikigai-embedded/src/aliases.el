;;; -*- lexical-binding: t -*-
;;; The fixed runtime under a generated ikigai alias file.
;;;
;;; Kept as real elisp in a real .el file rather than a Rust string literal: it is the only
;;; hand-written part, and burying it in nested escaping is how you end up shipping
;;; `(concat "" " (replace-regexp-in-string ...` to someone's Emacs.
;;;
;;; Each call is a COMPLETE one-shot request. That is what makes these usable from anywhere
;;; elisp runs — `M-:`, a keybinding, org-babel, a hook — with no session to establish and
;;; no state to lose, and it sidesteps `urn:lisp:eval`'s per-eval isolation entirely.

(defgroup ikigai nil "Call ikigai resources from Emacs." :group 'tools)

(defcustom ikigai-program "ikigai"
  "The ikigai executable."
  :type 'string :group 'ikigai)

(defcustom ikigai-connect (expand-file-name "~/.ikigai/host.sock")
  "Kernel to talk to: a Unix socket path, or a quic:// URL.
Connecting to the STANDING host costs one process spawn; building an embedded
kernel per call would cost a great deal more."
  :type 'string :group 'ikigai)

(defun ikigai--quote (value)
  "Quote VALUE for the engine's argument parser."
  ;; The engine splits arguments on whitespace, so any value containing one needs
  ;; quoting, and an embedded quote needs escaping. Getting this wrong is how a
  ;; signature graph turns into `Ed25519 is not a valid RDF object'.
  (format "\"%s\"" (replace-regexp-in-string "\"" "\\\\\"" (format "%s" value))))

(defun ikigai--command (verb iri args)
  "Build the engine command line for VERB on IRI with ARGS (flat name/value list)."
  ;; Build the PAIRS separately and append. Seeding the accumulator with (verb iri) and
  ;; nreversing the lot puts the IRI first, and the engine then reads the IRI as the command
  ;; ("unknown command `urn:fn:toUpper'").
  (let (pairs)
    (while args
      (push (concat (car args) "=" (ikigai--quote (cadr args))) pairs)
      (setq args (cddr args)))
    (mapconcat #'identity (append (list verb iri) (nreverse pairs)) " ")))

(defun ikigai--call (verb iri args)
  "Issue VERB on IRI with ARGS and return the representation as a string."
  (let ((command (ikigai--command verb iri args))
        (buffer (generate-new-buffer " *ikigai*")))
    (unwind-protect
        (let ((code (call-process ikigai-program nil buffer nil
                                  "--plain" "--connect" ikigai-connect "-c" command)))
          (with-current-buffer buffer
            ;; Drop the engine's trailing status line ([computed] / [uncacheable]):
            ;; REPL furniture, not part of the representation.
            (goto-char (point-max))
            (when (re-search-backward "^\\[[^]]*\\]$" nil t)
              (delete-region (point) (point-max)))
            (let ((output (string-trim (buffer-string))))
              (if (zerop code)
                  output
                ;; Signal rather than return the text: a denial or a missing argument
                ;; must not reach the caller looking like a result.
                (error "ikigai: %s" output)))))
      (kill-buffer buffer))))
