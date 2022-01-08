<TeXmacs|1.99.2>

<style|manual>

<\body>
  <part|High-Level Introduction?><part|Detailed Instructions>

  <section|Tables or Volvelles>

  Hand computation for the procedures in this document can be performed
  either by using the Principal Tables to look up values, or by using
  volvelle wheels to look up values. \ While the volvelle wheels take time to
  cut out and assemble, they are generally easier to use than the tables when
  available.

  <section|Share Format>

  For 128-bit secret seeds, each share is 48 characters long. Shares begin
  with the three character prefix <verbatim|MS1>. This is followed by a six
  character header. The next 26-characters is the data portion. The last
  13-characters is the checksum.

  The header consists of:

  <\itemize>
    <item>The <strong|threshold> which is the value <math|k>, a digit between
    <verbatim|2> and <verbatim|9> inclusive, however Module 0 only supports
    <math|k\<leq\>3>. When secret splitting is not used, the a <verbatim|0>
    digit is placed here instead.

    <item>The <strong|identifier> which is four bech32 characters.

    <item>The <strong|share index> which is any bech32 character except for
    <verbatim|S>. The <verbatim|S> index is the <strong|secret index>. The
    data portion of the <strong|secret index> contains the secret seed.
  </itemize>

  Shares of one secret all have the same threshold and identifiers. If you
  have multiple secrets, you should use distinct identifiers for each secret
  so as not to mix-up shares of different secrets with each other. The
  identifiers are not considered secret themselves.

  <section|New Secret Seed>

  Generating a <math|k>-of-<math|n> scheme for a new random secret is most
  easily done by generating fresh random shares directly. This process
  generates a new random secret seed without directly revealing it.

  <\enumerate-numeric>
    <item>Choose a threshold <math|k> and total number of shares <math|n>
    that suits your needs. The threshold <math|k> must be 3 or less and
    <math|n> must be 31 or less.

    <item>Choose a 4 character identifier for your new secret seed. The
    identifier can be anything as long as it only uses the Bech32 character
    set. The identifier itself is not secret. However, the identifier should
    be unique for each secret seed.

    <item>Follow Section<nbsp><reference|NewSecret1> to generate the first
    <math|k> shares.

    <item>Follow Section<nbsp><reference|NewSecret2> to generate the
    remaining <math|n-k> shares.

    <item>Load your shares into your BIP-???? compliant wallet or use the
    Recover Secret Seed procedure in Section<nbsp><reference|RecoverSecret>
    to access your new secret seed value.

    <item>Copy and distribute your <math|n> shares into safe and secure
    locations. Remember that you will need to recover at least <math|k> of
    these shares to recover your secret seed. Also remember that anyone else
    who recovers <math|k> of these shares can also recover your secret seed.

    <item>Securely dispose of all worksheets you used in the generation
    procedure. If these worksheets are not securely disposed of, the could be
    used to recover your secret seed.
  </enumerate-numeric>

  <subsection|New Secret Seed: Stage 1><label|NewSecret1>

  Make <math|2k> copies of the Checksum Worksheet and save half of them for
  later.

  Fill out the header portion of <math|k> many Checksum Worksheets with your
  chosen threshold <math|k> and chosen ID. Place a unique share index on each
  worksheet starting with share <verbatim|A> on the first worksheet,
  <verbatim|C> on the second worksheet, and so on through the <math|k> first
  characters from the Bech32 character set. (Note that <verbatim|B> and
  <verbatim|I> are not part of the Bech32 character set and are omitted).
  However, if you are not splitting your secret, (i.e. <math|k=1>) see the
  special instructions below.

  Fill out the 26 character data portion of each Checksum Worksheet with
  random characters. Use the Random Character Worksheet to generate each
  random character.

  Follow the Checksum Worksheet instructions to generate a checksum for each
  worksheet.

  <strong|Critical Step:> Verify your checksum by copying each the 48
  character share onto an empty worksheet that you saved earlier. Follow the
  checksum verification instructions to verify each checksum. If any checksum
  fails to verify then make more copies of the Checksum worksheet and redo
  the checksum generation and checksum verification steps again.

  <strong|Failure to verify each checksum may lead to irrecoverable loss of
  the secret seed and funds.>

  <em|Special rules for k=1>: If you are not splitting your secret, then use
  a <verbatim|0> digit in the threshold place, and use the <verbatim|S>
  character in the share index place. Follow the same instructions for
  generating the data portion and the checksum.

  <subsection|New Secret Seed: Stage 2><label|NewSecret2>

  The remaining <math|n-k> are derived from the first <math|k> shares using
  the addition worksheet corresponding to the <math|k> value you have chosen.
  Label the entries of the addition worksheet with the share indices that you
  will be using. We recommend following the Bech32 character order following
  the last index you generated in Stage 1.

  Use the following procedure to derive a new share:

  <\enumerate-numeric>
    <item>Make a copy of the Addition Worksheet for the value of <math|k>
    that you are using and label the shares with the share indices from the
    shares you have already generated, <verbatim|A>, <verbatim|C> and
    <verbatim|D> if <math|k=3>. Label the Final Share Index with the new
    share index you want to derive.

    <item>In the derivation table for your value of <math|k>, find the column
    corresponding to the new share index you want to derive. Fill in the
    symbols on the Addition Worksheet with the symbols from that column next
    to the share index for each row.

    <item>Follow the Translation Worksheet instructions derive the new share.
  </enumerate-numeric>

  <section|Recover Secret Seed><label|RecoverSecret>

  Normally you would not recover a secret seed yourself, and instead load
  shares into a BIP-???? compliant wallet. However, you can recover the
  secret seed by hand if no compatible wallets are available or whatever
  other reason you might have.

  The recovery procedure uses exactly <math|k> many shares. If you have more
  than <math|k> many shares, you can select any <math|k> of them and set the
  other shares aside.

  Use the following procedure to recover the share:

  <\enumerate-numeric>
    <item>For each share, fill in a Checksum Worksheet and verify the
    checksum. If a checksum fails to verify, you may have made an error on
    your worksheet, or there may be an error in your share data. If there is
    an error in your share data, you can try substituting the share with a
    different one. Otherwise you will need to perform the Error Correction
    Procedure on your share, which will involve the assistance of a digital
    computer.

    <item>Make a copy of the Addition Worksheet for the value of <math|k>
    that you are using and label the shares with the share indices from the
    shares you have selected to recover from, and label the Final Share Index
    as <samp|S>.

    <item>You can fill in the symbols for each share on the Addition
    Worksheet using either the table lookup, or the volvelle lookup:

    <em|Table lookup <math|k=2>>: Fill in the symbol from the Recover table
    by finding the column with the associated share, and the row for the
    other share.

    <em|Volvelle lookup <math|k=2>>: Turn the Recovery Volvelle to point to
    the share being considered. Find the symbol pointed to under the other
    share index on the wheel and fill in that symbol next to the share we are
    considering on the Addition Worksheet.

    <em|Table lookup <math|k=3>>: Finding the column with the associated
    share. Lookup the two symbols from the two rows corresponding to the two
    other shares. Make a note of these two symbols on a scrap piece of paper.
    Use the multiplication table to multiply the the two symbols and fill in
    that share's symbol on the Addition Worksheet with the resulting product.

    <em|Volvelle lookup <math|k=3>>: Turn the Recovery Volvelle to point to
    the share being considered. Find the two symbol pointed to under the
    other share indices on the wheel. Turn the multiplication wheel to the
    first of these two symbols. Find the second symbol on the lower ring, and
    lookup the symbol it is pointing to. Fill that symbol next to the share
    we are considering on the Addition Worksheet.

    <item>Repeat step 3 for each share on the Addition worksheet.

    <em|Tip>: For <math|k=2> the two symbols will always be opposite each
    other on the Recovery Volvelle and are connect by a grey line.

    <item>Follow the Translation Worksheet instructions recover the secret
    share.

    <item>After completing the checksum verification you may run the Binary
    Worksheet on the secret share to convert the secret seed into binary
    format.
  </enumerate-numeric>

  <section|Random Character Worksheet>

  This procedure generates random Bech32 characters from dice using a
  debiasing technique. As long as the procedure is followed carefully and
  correctly, even low-quality consumer dice can be safely used to generate
  128-bits of near perfect randomness.

  You will need the following items:

  <\itemize>
    <item>The character tree below.

    <item>The dice track page.

    <item>Five distinct and distinguishable dice.

    <item>Six coins or other small markers.

    <item>One cup for shaking and rolling the dice.
  </itemize>

  It is important that the five dice be distinguishable. They can be
  different colours or, if you have adventure dice, you they can have
  different number of sides. Label the five dice tracks by the colour or
  other distinguishing features of each die.

  Use the following procedure to generate one random character:

  <\enumerate-numeric>
    <item>Place one coin at the top of the character tree.

    <item>Place the five dice together in the cup, shake, and roll the dice.
    Mark the results of each die by placing a coin on the track corresponding
    to each distinguished die's result.

    <item>Place the five dice together in the cup again, shake, and roll the
    dice. Mark the results of each die by placing the die itself on its own
    track at the value it rolled.

    <item>If any die and maker on on the same spot on its track, remove
    <strong|both> the marker and the die. Repeat steps 2 and 3 for any
    removed dice to replace the marker and the die. Keep repeating until it
    is no die and marker on on the same spot on the track.

    <item>Starting with the first track, move the coin on the character tree
    down and to the left, if the die on the first track is to the left of the
    marker. Otherwise, if the die on the first track is to the right of the
    marker, move the coin on the character tree down and to the right.

    <item>Repeat step 5 for the second, third, forth, and fifth dice tracks.

    <item>Record the character under where the coin on the character tree
    ends up on as your random character.

    <item>Clear of all dice and markers. Return to Step 1 if you need to
    generate more characters.
  </enumerate-numeric>

  <strong|It is critical in step 4 to remove both the dice and marker.>

  <section|Checksum Worksheet>

  <section|Translation Worksheet>

  The Translation Worksheet is used by both the secret recovery procedure and
  the share derivation procedure. This procedure translate <math|k> shares
  and sum the results to get produce a share. Before starting the Translation
  Procedure the Translation Worksheet should already have <math|k> many share
  index and symbols filled in.

  The Translation procedure can either be done using lookup tables or using
  volvelles.

  <\enumerate-numeric>
    <item>Translate the first share using the first symbol.

    <em|Lookup Table Method>: Find the column in the Translation table for
    the symbol. Translate each character of the share after the
    <verbatim|MS1> prefix by looking up the row for that character and
    writing the resulting character.

    <em|Volvelle Method>: Turn the multiplication wheel to the symbol, then
    flip the disc over to the translations side. Translate each character of
    the share after the <verbatim|MS1> prefix by looking up the character on
    the lower ring and writing the resulting character it points to.

    <item>Repeat Step 1 for the second share using the second symbol.

    <item>Add the two translated shares, character by character.

    <em|Lookup Table Method>: For each position, find the row/column of two
    translated characters in the Addition Table and write the resulting
    character in the position below them. Addition is symmetric so the two
    characters can be looked up in either order.

    <em|Volvelle Method>: For each position, turn the addition wheel to the
    character of one translation and lookup the character from the other
    translation in the interior of the wheel. Write the resulting character
    in the position below them. Addition is symmetric so two characters can
    be looked up in either order.

    <item>If <math|k\<gtr\>2> then repeat steps 1-3, translating each
    additional share and adding it to the previous sum until all shares are
    translated and added together.

    <item><strong|Critical Step:> Verify the resulting share. It should have
    a correct header with a correct threshold, identity, and have the correct
    share index. Copy the share into a fresh checksum worksheet and follow
    the checksum verification step. If the checksum is not valid then you
    have made and error either in the checksum verification procedure or in
    the share derivation procedure and you must repeat the procedure.
  </enumerate-numeric>

  <em|Tip:> You are more likely to make an error in the checksum verification
  procedure itself. To help guide the checksum verification you can run the
  translate procedure on the bottom diagonal of the checksum worksheets for
  each share. Fill in the resulting in the bottom diagonal of the
  verification worksheet of your new share. As you proceed with the checksum
  verification procedure you should encounter the same character on the lower
  diagonal that you have prefilled. If not, you have made an error, either in
  the checksum verification up to that point, or in a column of your addition
  worksheet that is before that point.

  <section|Binary Conversion Worksheet>

  <section|Error Correction>

  <section|Volvelle Assembly>
</body>

<initial|<\collection>
</collection>>

<\references>
  <\collection>
    <associate|NewSecret1|<tuple|3.1|?>>
    <associate|NewSecret2|<tuple|3.2|?>>
    <associate|NewStage1|<tuple|2.1|?>>
    <associate|RecoverSecret|<tuple|4|?>>
    <associate|auto-1|<tuple|I|?>>
    <associate|auto-10|<tuple|6|?>>
    <associate|auto-11|<tuple|7|?>>
    <associate|auto-12|<tuple|8|?>>
    <associate|auto-13|<tuple|9|?>>
    <associate|auto-14|<tuple|10|?>>
    <associate|auto-15|<tuple|3.8|?>>
    <associate|auto-2|<tuple|II|?>>
    <associate|auto-3|<tuple|1|?>>
    <associate|auto-4|<tuple|2|?>>
    <associate|auto-5|<tuple|3|?>>
    <associate|auto-6|<tuple|3.1|?>>
    <associate|auto-7|<tuple|3.2|?>>
    <associate|auto-8|<tuple|4|?>>
    <associate|auto-9|<tuple|5|?>>
  </collection>
</references>

<\auxiliary>
  <\collection>
    <\associate|toc>
      <vspace*|2fn><with|font-series|<quote|bold>|math-font-series|<quote|bold>|font-size|<quote|1.19>|I<space|2spc>High-Level
      Introduction?> <datoms|<macro|x|<repeat|<arg|x>|<with|font-series|medium|<with|font-size|1|<space|0.2fn>.<space|0.2fn>>>>>|<htab|5mm>>
      <no-break><pageref|auto-1><vspace|1fn>

      <vspace*|2fn><with|font-series|<quote|bold>|math-font-series|<quote|bold>|font-size|<quote|1.19>|II<space|2spc>Detailed
      Instructions> <datoms|<macro|x|<repeat|<arg|x>|<with|font-series|medium|<with|font-size|1|<space|0.2fn>.<space|0.2fn>>>>>|<htab|5mm>>
      <no-break><pageref|auto-2><vspace|1fn>

      1<space|2spc>Tables or Volvelles <datoms|<macro|x|<repeat|<arg|x>|<with|font-series|medium|<with|font-size|1|<space|0.2fn>.<space|0.2fn>>>>>|<htab|5mm>>
      <no-break><pageref|auto-3>

      2<space|2spc>Share Format <datoms|<macro|x|<repeat|<arg|x>|<with|font-series|medium|<with|font-size|1|<space|0.2fn>.<space|0.2fn>>>>>|<htab|5mm>>
      <no-break><pageref|auto-4>

      3<space|2spc>New Secret Seed <datoms|<macro|x|<repeat|<arg|x>|<with|font-series|medium|<with|font-size|1|<space|0.2fn>.<space|0.2fn>>>>>|<htab|5mm>>
      <no-break><pageref|auto-5>

      <with|par-left|<quote|1tab>|3.1<space|2spc>New Secret Seed: Stage 1
      <datoms|<macro|x|<repeat|<arg|x>|<with|font-series|medium|<with|font-size|1|<space|0.2fn>.<space|0.2fn>>>>>|<htab|5mm>>
      <no-break><pageref|auto-6>>

      <with|par-left|<quote|1tab>|3.2<space|2spc>New Secret Seed: Stage 2
      <datoms|<macro|x|<repeat|<arg|x>|<with|font-series|medium|<with|font-size|1|<space|0.2fn>.<space|0.2fn>>>>>|<htab|5mm>>
      <no-break><pageref|auto-7>>

      4<space|2spc>Recover Secret Seed <datoms|<macro|x|<repeat|<arg|x>|<with|font-series|medium|<with|font-size|1|<space|0.2fn>.<space|0.2fn>>>>>|<htab|5mm>>
      <no-break><pageref|auto-8>

      5<space|2spc>Random Character Worksheet
      <datoms|<macro|x|<repeat|<arg|x>|<with|font-series|medium|<with|font-size|1|<space|0.2fn>.<space|0.2fn>>>>>|<htab|5mm>>
      <no-break><pageref|auto-9>

      6<space|2spc>Checksum Worksheet <datoms|<macro|x|<repeat|<arg|x>|<with|font-series|medium|<with|font-size|1|<space|0.2fn>.<space|0.2fn>>>>>|<htab|5mm>>
      <no-break><pageref|auto-10>

      7<space|2spc>Translation Worksheet <datoms|<macro|x|<repeat|<arg|x>|<with|font-series|medium|<with|font-size|1|<space|0.2fn>.<space|0.2fn>>>>>|<htab|5mm>>
      <no-break><pageref|auto-11>

      8<space|2spc>Binary Conversion Worksheet
      <datoms|<macro|x|<repeat|<arg|x>|<with|font-series|medium|<with|font-size|1|<space|0.2fn>.<space|0.2fn>>>>>|<htab|5mm>>
      <no-break><pageref|auto-12>

      9<space|2spc>Error Correction <datoms|<macro|x|<repeat|<arg|x>|<with|font-series|medium|<with|font-size|1|<space|0.2fn>.<space|0.2fn>>>>>|<htab|5mm>>
      <no-break><pageref|auto-13>

      10<space|2spc>Volvelle Assembly <datoms|<macro|x|<repeat|<arg|x>|<with|font-series|medium|<with|font-size|1|<space|0.2fn>.<space|0.2fn>>>>>|<htab|5mm>>
      <no-break><pageref|auto-14>
    </associate>
  </collection>
</auxiliary>