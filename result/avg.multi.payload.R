
library(dplyr, warn.conflicts=F)

args <- commandArgs(trailingOnly = TRUE)
 
df = read.csv(args[1])

 
df_hs = df %>% group_by(type, msg_len) %>% summarise(
                                                         avg_cipher_len=mean(pmsg_enc_len + n_enc_len/n), 
                                                         .groups = 'drop')
df_hs %>% write.csv(args[2] , row.names = F)


