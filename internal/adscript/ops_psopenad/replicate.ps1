        # Config rejects ForceSync at construction on this dialect, so this
        # fragment should be unreachable. It exists so that a future code path
        # reaching it fails loudly and by name rather than as a missing fragment.
        throw [System.NotSupportedException]::new(
            'Forced replication is not available with the PSOpenAD dialect: it needs a rootDSE modify ' +
            'writing replicateSingleObject, which PSOpenAD cannot express. Use the polling replication ' +
            'wait instead (Replication.Wait without ForceSync).')
