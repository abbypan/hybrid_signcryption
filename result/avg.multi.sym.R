
library(dplyr, warn.conflicts=F)

args <- commandArgs(trailingOnly = TRUE)
 
df = read.csv(args[1])

 
df_hs = df %>% group_by(msg_len) %>% summarise(
                                                         avg_sym_enc=mean(pmsg_enc_time*1000), 
                                                         avg_sym_dec=mean(pmsg_dec_time*1000), 
                                                         .groups = 'drop')
df_hs %>% write.csv(args[2] , row.names = F)


