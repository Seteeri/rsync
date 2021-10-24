#{
    https://code.activestate.com/recipes/577518-rsync-algorithm/

    Optimize make-delta: Use binary tree instead of list/index

    Optimize rd-block: Read block as single number [DONE]

        To convert bignum to bytes: shift and mask:

        int orig = 0x0403;
        byte dest[4];

        # num -> bytes
        dest[0] =  orig        & 0xFF;
        dest[1] = (orig >> 8)  & 0xFF;
        dest[2] = (orig >> 16) & 0xFF;
        dest[3] = (orig >> 24) & 0xFF;
        ...
        dest[n] = (orig >> n*8) & 0xFF (bin:11111111,int:255)

        Limit of N = number of bits in bignum = (logN/log2)+1 or (int)log2(N)+1
        divide this by 8 to get number of iterations
        log requires math library

        or

        bit traversal so shift until result is zero

        # bytes -> num
        orig = (dest[3] << 24) + (dest[2] << 16) + (dest[1] << 8) + dest[0]

    Optimize blockchecksum:
        build list, return flipped
        or
        build block list, make lists

}#

(symbols 'rsync 'pico)

(def '*SZ-BLOCK  4096)
(def '*SZ-BUFFER 4096)

(de md5 (Str)
  # Passing list of bytes...md5 expecting a string
  # Could have rd-block return a num and pass that
  # Also would need to calculate length of the num using log
  (pack
    (mapcar '((B) (pad 2 (hex B)))
      (native "libcrypto.so" "MD5" '(B . 16) # Ret *md
          Str          # unsigned char *d
          (length Str) # unsigned long n
          '(NIL (16))  # unsigned char *md (16-bytes)
      ))))

(de rd-block (Block-Size)
  # Returns list of bytes
  (make
    (let Cnt 0
      # loop until block-size or EOF
      (until (or (= Cnt Block-Size)
              (eof))
        (when (rd 1)
            (inc 'Cnt)
            (link @))))))

(de make-delta (Data-Stream Remote-Signature Block-Size Max-Buffer)

  (let (Remote-Weak (car Remote-Signature)
        Remote-Strong (cdr Remote-Signature)
        Match T
        Init T
        Match-Block 0
        Delta-Queue ()
        Window NIL
        Rcs NIL) # Checksum A B

    # make-delta-queue

    (in Data-Stream

      (loop

        (when (and Match Init)
          (setq
            Window (rd-block Block-Size))
            Rcs (weakchecksum Window))

        (NIL

          (if (and
                (setq Match-Block
                    (index (car Rcs)
                        (nth Remote-Weak (inc Match-Block))))
                (setq Match-Block
                    (index (md5 Window) # strong hash
                        (nth Remote-Strong Match-Block))))

              (t
                (on Match)
                # push to end...other poss methods
                (conc Delta-Queue (cons Match-Block)))

              (nil
                (off Match)
                (setq Rcs (handle-nomatch Data-Stream Block-Size Init Rcs)))))))

    # make-delta-struct

    # TODO: use (make)
    (let Delta-Structure (Block-Size)

      (for Element Delta-Queue

          # Element is a number or list or NIL
          (if (num? Element)

              (conc Delta-Queue (cons Element))

              (when Element

                (conc Delta-Queue Element))))

      Delta-Structure)))


(de handle-nomatch (Data-Stream Block-Size Init Rcs)

  (let (Newbyte NIL
        Tailsize 0)

    (when Init

      (if (setq Newbyte (in Data-Stream (rd 1)))

          (conc Window (cons Newbyte))

          (setq
            Newbyte 0
            Tailsize (% (tell Data-Stream) Block-Size)
            Init NIL))) # turn off data-stream

    (if (and (not Init)
            (<= (length Window) Tailsize))

        (nil
          (conc Delta-Queue Window))


        (setq Oldbyte (pop 'Window))

        (let Last (last Delta-Queue)

          (if (pair Last)

              (conc Last Oldbyte)
              (conc Delta-Queue Oldbyte)))

        # return checksum...and init?
        (let ((NIL A B) Rcs)

          (rollingchecksum Oldbyte Newbyte A B Block-Size)))))


(de blockchecksums (Instream Block-Size)

  (let (Weak-Hashes ()
        Strong-Hashes ())

      (in Instream

        (while (rd-block Block-Size)

            (push 'Weak-Hashes (car (weakchecksum @)))
            (push 'Strong-Hashes (md5 @))))

      (cons (flip Weak-Hashes) (flip Strong-Hashes))))


(de patchstream (Instream Outstream Delta)

  (let Block-Size (car Delta)

    (for Element (cdr Delta)

      (when (and (num? Element) Block-Size)

        (%@ "fseek" Instream (* Element Block-Size) 0) # whence=0=abs
        (setq Element
            (in Instream (rd-block Block-Size))))

      # wr element (list of bytes) to outstream
      (out Outstream (mapc wr Element)))))


(de rollingchecksum (Removed New A B Block-Size)
  (dec 'A Removed New)
  (dec 'B (- (* Removed Block-Size) A))
  (list
    (| (>> -16 B) A)
    A
    B))


(de weakchecksum (Data)

  # Data is list of bytes
  (let (A 0
        B 0
        L (length Data))

    (for (I . X) Data

      (inc 'A X)
      (inc 'B (* (- L I) X)))

    (list
      (| (>> -16 B) A)
      A
      B)))


(de weakchecksum-num (Data)

  # Data is list of bytes
  (let (A 0
        B 0
        L (length Data))

    (for (I . X) Data
      (inc 'A X)
      (inc 'B (* (- L I) X)))

    (list
      (| (>> -16 B) A)
      A
      B)))


(de tst ())
