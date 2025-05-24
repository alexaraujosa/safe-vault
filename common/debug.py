G_SERVER_DEBUG = False
G_SERVER_CONFIG_DEBUG = True       # Enabling this will save the config in every operation
G_CLIENT_DEBUG = False             # Currently not used
G_DEBUG_PACKET_READ_FULLY = False


def trace(*args, g_debug=False):
    if (g_debug):
        print(*args)
