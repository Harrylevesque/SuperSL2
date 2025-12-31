from flow.ssh import working_file


print(working_file(
    con_uuid="test-con-uuid",
    svu_uuid="test-svu-uuid",
    sv_uuid="test-sv-uuid",
    pubkey="ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7...",
    ip="0.0.0.0"
))