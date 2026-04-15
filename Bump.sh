#!/usr/bin/env sh

APP_NAME=$(basename "$(pwd)")
VERSION_FILE=$(head -1 < VERSION)
VERSION_NUMBER=$(echo "$VERSION_FILE" | cut -d'-' -f1 | cut -d'+' -f1)
PRE_RELEASE=$(echo "$VERSION_FILE" | cut -d'-' -f2 | cut -d'+' -f1)
BUILD=$(echo "$VERSION_FILE" |cut -d'-' -f2 | cut -d'+' -f2)
if [ "$PRE_RELEASE" = "$VERSION_NUMBER" ]; then
    PRE_RELEASE=""
fi
if [ "$BUILD" = "$VERSION_NUMBER" ] || [ "$BUILD" = "$PRE_RELEASE" ]; then
    BUILD=""
fi

MAJOR=$(echo "$VERSION_NUMBER" | cut -d'.' -f1)
MINOR=$(echo "$VERSION_NUMBER" | cut -d'.' -f2)
PATCH=$(echo "$VERSION_NUMBER" | cut -d'.' -f3)
PRE_RELEASE_IDENTIFIER=$(echo "$PRE_RELEASE." | cut -d'.' -f2)

_usage() {
    echo "Usage: ./$(basename $0) (major|minor|patch|rc|release)"
    echo ""
    echo "Current Version"
    echo "---------------"
    echo ""
    echo "MAJOR       : $MAJOR"
    echo "MINOR       : $MINOR"
    echo "PATCH       : $PATCH"
    echo "PRE_RELEASE : $PRE_RELEASE"
    echo "BUILD       : $BUILD"
    echo ""
    exit 1
}

_build_version() {
    if [ -z "$MAJOR" ]; then
        MAJOR=0
    fi
    if [ -z "$MINOR" ]; then
        MINOR=0
    fi
    if [ -z "$PATCH" ]; then
        PATCH=0
    fi
    VERSION_NUMBER="${MAJOR}.${MINOR}.${PATCH}"
    if [ -n "$PRE_RELEASE" ]; then
        PRE_RELEASE="-$PRE_RELEASE"
    fi
    if [ -n "$BUILD" ]; then
        BUILD="+$BUILD"
    fi
    echo "${VERSION_NUMBER}${PRE_RELEASE}${BUILD}" > VERSION
}

_sync_erlang_versions() {
    V="$1"
    sed -i "s/\({release, {[^,]*, \)\"[^\"]*\"/\1\"${V}\"/" rebar.config
    APP_SRC=$(find apps/*/src -name '*.app.src' 2>/dev/null | head -1)
    if [ -n "$APP_SRC" ]; then
        sed -i "s/{vsn, \"[^\"]*\"}/{vsn, \"${V}\"}/" "$APP_SRC"
    fi
}

_bump_major() {
    if [ -n "$MAJOR" ]; then
        MAJOR=$((MAJOR+1))
        MINOR=0
        PATCH=0
    fi
    git stash --include-untracked
    _build_version
    VERSION_GIT=$(head -1 < VERSION)
    _sync_erlang_versions "$VERSION_GIT"
    git add VERSION rebar.config
    APP_SRC=$(find apps/*/src -name '*.app.src' 2>/dev/null | head -1)
    [ -n "$APP_SRC" ] && git add "$APP_SRC"
    git commit -m "Bumping new major ${VERSION_GIT}"
    git tag -a "${APP_NAME}/v${VERSION_GIT}" -m "Release ${APP_NAME} v${VERSION_GIT}"
    git push origin "${APP_NAME}/v${VERSION_GIT}"
    git push origin
    git stash pop
}

_bump_minor() {
    if [ -n "$MINOR" ]; then
        MINOR=$((MINOR+1))
        PATCH=0
    fi
    git stash --include-untracked
    _build_version
    VERSION_GIT=$(head -1 < VERSION)
    _sync_erlang_versions "$VERSION_GIT"
    git add VERSION rebar.config
    APP_SRC=$(find apps/*/src -name '*.app.src' 2>/dev/null | head -1)
    [ -n "$APP_SRC" ] && git add "$APP_SRC"
    git commit -m "Bumping new minor ${VERSION_GIT}"
    git tag -a "${APP_NAME}/v${VERSION_GIT}" -m "Release ${APP_NAME} v${VERSION_GIT}"
    git push origin "${APP_NAME}/v${VERSION_GIT}"
    git push origin
    git stash pop
}

_bump_patch() {
    if [ -n "$PATCH" ]; then
        PATCH=$((PATCH+1))
    fi
    git stash --include-untracked
    _build_version
    VERSION_GIT=$(head -1 < VERSION)
    _sync_erlang_versions "$VERSION_GIT"
    git add VERSION rebar.config
    APP_SRC=$(find apps/*/src -name '*.app.src' 2>/dev/null | head -1)
    [ -n "$APP_SRC" ] && git add "$APP_SRC"
    git commit -m "Bumping new patch ${VERSION_GIT}"
    git tag -a "${APP_NAME}/v${VERSION_GIT}" -m "Release ${APP_NAME} v${VERSION_GIT}"
    git push origin "${APP_NAME}/v${VERSION_GIT}"
    git push origin
    git stash pop
}

_bump_rc() {
    if [ -z "$PRE_RELEASE_IDENTIFIER" ]; then
        PRE_RELEASE_IDENTIFIER=1
    else
        PRE_RELEASE_IDENTIFIER=$((PRE_RELEASE_IDENTIFIER+1))
    fi
    PRE_RELEASE="rc.$PRE_RELEASE_IDENTIFIER"
    git stash --include-untracked
    _build_version
    VERSION_GIT=$(head -1 < VERSION)
    _sync_erlang_versions "$VERSION_GIT"
    git add VERSION rebar.config
    APP_SRC=$(find apps/*/src -name '*.app.src' 2>/dev/null | head -1)
    [ -n "$APP_SRC" ] && git add "$APP_SRC"
    git commit -m "Bumping new release candidate ${VERSION_GIT}"
    git tag -a "${APP_NAME}/v${VERSION_GIT}" -m "Release ${APP_NAME} v${VERSION_GIT}"
    git push origin "${APP_NAME}/v${VERSION_GIT}"
    git push origin
    git stash pop
}

_bump_release() {
    PRE_RELEASE=""
    BUILD=""
    git stash --include-untracked
    _build_version
    VERSION_GIT=$(head -1 < VERSION)
    _sync_erlang_versions "$VERSION_GIT"
    git add VERSION rebar.config
    APP_SRC=$(find apps/*/src -name '*.app.src' 2>/dev/null | head -1)
    [ -n "$APP_SRC" ] && git add "$APP_SRC"
    git commit -m "Bumping new release ${VERSION_GIT}"
    git tag -a "${APP_NAME}/v${VERSION_GIT}" -m "Release ${APP_NAME} v${VERSION_GIT}"
    git push origin "${APP_NAME}/v${VERSION_GIT}"
    git push origin
    git stash pop
}

if [ $# != 1 ]; then
    _usage
fi

case "$1" in
    major)
        _bump_major
        ;;
    minor)
        _bump_minor
        ;;
    patch)
        _bump_patch
        ;;
    rc)
        _bump_rc
        ;;
    release)
        _bump_release
        ;;
    *)
        _usage
        ;;
esac
