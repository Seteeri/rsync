(de rsyncdelta (Data Remote-Signatures Blocksize) (default Blocksize 4096)
  #{
  
    Generates a binary patch when supplied with the weak and strong
    hashes from an unpatched target and a readable stream for the
    up-to-date data. The blocksize must be the same as the value
    used to generate remotesignatures.
    
  }#
  
  (let ((Weak-Remote . Strong-Remote) Remote-Signatures # <- blockchecksums
        Match T
        Match-Block -1
        Deltas () # deque
        Window NIL
        (Checksum A B) '(NIL NIL NIL))

    (while Data

      (when (and Match Data)
        # Whenever there is a match or the loop is running for the first
        # time, populate the window using weakchecksum instead of rolling
        # through every single byte which takes at least twice as long. 
        
        (for X (cut Blocksize 'Data) (fifo 'Window X))
        (let ((X Y Z) (weakchecksum Window)) 
          (setq Checksum X A Y B Z)))

      # python index = element start end

      # If there are two identical weak checksums in a file, and the
      # matching strong hash does not occur at the first match, it will
      # be missed and the data sent over. May fix eventually, but this
      # problem arises very rarely.                
      
      (let (Match-Weak (setq Match-Block (index Checksum (nth Weak-Remote (+ Match-Block 1))))
            Match-Strong (setq Match-Block (index (md5 Window) (nth Strong-Remote Match-Block))))
            
        (if (and Match-Weak Match-Strong)
        
            (prog
              (setq Match T)
              # push to end of deltas
              (fifo 'Deltas Match-Block))
              
            # The weakchecksum did not match
            (setq Match NIL)
            
            (let Byte (pop 'Data)
            
              (if Byte 
                  (push 'Window Byte)
                  (setq 
                    Byte 0
                    Tail-Size (% (length Data) Blocksize))
                    Data NIL))

              (if (and 
                    (not Data) 
                    (<= (length Window) Tail-Size))

                  # The likelihood that any blocks will match after this is
                  # nearly nil so call it quits.            
                  (fifo 'Deltas Window)
                  # break loop

                  # Yank off the extra byte and calculate the new window checksum
                  (setq Old (fifo 'Window)) # popleft
                  (let ((X Y Z) (rollingchecksum Old Byte A B Blocksize)) 
                    (setq Checksum X A Y B Z))

                  # Add the old byte the file delta. This is data that was not found
                  # inside of a matching block so it needs to be sent to the target.
                  # try: deltaqueue[-1].append(oldbyte)
                  # except (AttributeError, IndexError): deltaqueue.append([oldbyte])              

                  (if (last Deltas)
                      (conc @ (cons Old))
                      (fifo 'Deltas Old)))))))
           
    # Return a delta that starts with the blocksize and 
    # converts all iterables to bytes.
    (let Deltastruct (list Blocksize)
      (for X Deltas
        (cond
          ((num? X) (push 'Deltastruct X))
          ((and X (pair X))  (push 'Deltastruct (cons X)))
          (T (quit "???"))))
      Deltastruct)))

(de blockchecksums (In Blocksize) (default Blocksize 4096)
  #{
  
    Returns a list of weak and strong hashes for each block of the
    defined size for the given data stream.
    
  }#  
  (use (Weak Strong Block)
    (while (setq Block (cut Blocksize 'In))
      (push 'Weak (car (weakchecksum Block)))
      (push 'Strong (md5 Block)))
    (cons
      (flip Weak)
      (flip Strong))))

(de patchstream (In Out Delta)
  #{
  
    Patches instream using the supplied delta and write the resulting
    data to outstream  
    
  }#
  (let Blocksize (car Delta)
    (for X (cdr Delta)
      (when (and (num? X) Blocksize)
        # Seek to pos in list of bytes, read list of bytes
        (setq X (head Blocksize (nth In (* X Blocksize)))))
      # append list to out
      (conc
        Out
        X))))

(de rollingchecksum (Removed New A B Blocksize) (default Blocksize 4096)
  #{
  
    Generates a new weak checksum when supplied with the internal state
    of the checksum calculation for the previous window, the removed
    byte, and the added byte.
    
  }#  
  (dec 'A (- Removed New))
  (dec 'B (- (* Removed Blocksize) A))
  (list (| (>> -16 B) A) A B))

(de weakchecksum (Data)
  # Generates a weak checksum from an iterable set of bytes.
  (let (A 0
        B 0
        L (length Data))
    (for (I . X) Data
      (inc 'A X)
      (inc 'B (* (- L I) X)))
    (list (| (>> -16 B) A) A B)))

(let Str "The quick brown fox jumped over the lazy dog's back"
   (pack
      (mapcar '((B) (pad 2 (hex B)))
         (native "libcrypto.so" "MD5" '(B . 16) Str (length Str) '(NIL (16))) ) ) )
