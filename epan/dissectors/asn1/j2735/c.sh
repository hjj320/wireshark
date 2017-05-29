#!/bin/sh

tr -d '\r' < J2735_201603DA.asn |
sed 's/DSRC\.//' | sed 's/REGION\.//' | 
sed 's/AddGrpB\.//' | sed 's/AddGrpC\.//' | 
sed 's/NTCIP\.//' | sed 's/ITIS\.//' | 
sed 's/ITIScodes(523\.\.541)/INTEGER(523\.\.541)/' | 
awk ' NR >= 70 && NR <= 75 { l = l RS $0; next } NR == 80 { $0 = $0 l }
      NR == 5158 || NR == 5194 || NR == 5256 || NR == 5355 { $1 = $1 "-addGrpB" }
      NR == 5351 { gsub($NF, "Elevation-addGrpB,") } 1' > J2735_201603DA_fix.asn
