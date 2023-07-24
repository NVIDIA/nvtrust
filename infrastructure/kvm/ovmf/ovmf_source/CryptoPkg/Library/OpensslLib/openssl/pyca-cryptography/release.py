# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import getpass
import glob
import io
import os
import subprocess
import time
import zipfile

import click

import requests


def run(*args, **kwargs):
    print("[running] {0}".format(list(args)))
    subprocess.check_call(list(args), **kwargs)


def wait_for_build_complete_github_actions(session, token, run_url):
    while True:
        response = session.get(
            run_url,
            headers={
                "Content-Type": "application/json",
                "Authorization": "token {}".format(token),
            },
        )
        response.raise_for_status()
        if response.json()["conclusion"] is not None:
            break
        time.sleep(3)


def download_artifacts_github_actions(session, token, run_url):
    response = session.get(
        run_url,
        headers={
            "Content-Type": "application/json",
            "Authorization": "token {}".format(token),
        },
    )
    response.raise_for_status()

    response = session.get(
        response.json()["artifacts_url"],
        headers={
            "Content-Type": "application/json",
            "Authorization": "token {}".format(token),
        },
    )
    response.raise_for_status()
    paths = []
    for artifact in response.json()["artifacts"]:
        response = session.get(
            artifact["archive_download_url"],
            headers={
                "Content-Type": "application/json",
                "Authorization": "token {}".format(token),
            },
        )
        with zipfile.ZipFile(io.BytesIO(response.content)) as z:
            for name in z.namelist():
                if not name.endswith(".whl"):
                    continue
                p = z.open(name)
                out_path = os.path.join(
                    os.path.dirname(__file__),
                    "dist",
                    os.path.basename(name),
                )
                with open(out_path, "wb") as f:
                    f.write(p.read())
                paths.append(out_path)
    return paths


def fetch_github_actions_wheels(token, version):
    session = requests.Session()

    response = session.get(
        (
            "https://api.github.com/repos/pyca/cryptography/actions/workflows/"
            "wheel-builder.yml/runs?event=push"
        ),
        headers={
            "Content-Type": "application/json",
            "Authorization": "token {}".format(token),
        },
    )
    response.raise_for_status()
    run_url = response.json()["workflow_runs"][0]["url"]
    wait_for_build_complete_github_actions(session, token, run_url)
    return download_artifacts_github_actions(session, token, run_url)


@click.command()
@click.argument("version")
def release(version):
    """
    ``version`` should be a string like '0.4' or '1.0'.
    """
    github_token = getpass.getpass("Github person access token: ")

    # Tag and push the tag (this will trigger the wheel builder in Actions)
    run("git", "tag", "-s", version, "-m", "{0} release".format(version))
    run("git", "push", "--tags")

    # Generate and upload vector packages
    run("python", "setup.py", "sdist", "bdist_wheel", cwd="vectors/")
    packages = glob.glob(
        "vectors/dist/cryptography_vectors-{0}*".format(version)
    )
    run("twine", "upload", "-s", *packages)

    # Generate sdist for upload
    run("python", "setup.py", "sdist")
    sdist = glob.glob("dist/cryptography-{0}*".format(version))

    # Wait for Actions to complete and download the wheels
    github_actions_wheel_paths = fetch_github_actions_wheels(
        github_token, version
    )

    # Upload sdist and wheels
    run("twine", "upload", "-s", *sdist)
    run("twine", "upload", *github_actions_wheel_paths)


if __name__ == "__main__":
    release()
