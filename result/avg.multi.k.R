
library(dplyr, warn.conflicts=F)

args <- commandArgs(trailingOnly = TRUE)
 
df = read.csv(args[1])

 
df_hs = df %>% group_by(type, n) %>% summarise(
                                                         avg_k_enc_total=mean(n_enc_time*1000), 
                                                         avg_k_enc=mean(n_enc_time*1000/n), 
                                                         avg_k_dec=mean(n_dec_time*1000/n), 
                                                         .groups = 'drop')
df_hs %>% write.csv(args[2] , row.names = F)


