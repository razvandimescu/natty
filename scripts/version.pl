#!/usr/bin/env perl
use strict;
use warnings;
use File::Basename qw(dirname);
use File::Spec;

my $semver = qr/\d+\.\d+\.\d+/;
my $version_in_text = qr/(?<![\d.])$semver(?!\.?\d)/;
my $svg = qr/<svg\b.*?<\/svg>/s;
my $package_version = qr/^(\[package\]\n(?:(?!\[).*\n)*?version = ")($semver)"/m;
my $usage = "usage: scripts/version.pl check | scripts/version.pl set X.Y.Z\n";

sub lock_entry {
    my ($name) = @_;
    return qr/^(name = "\Q$name\E"\nversion = ")($semver)"/m;
}

my $source = ['Cargo.toml', 'package version', $package_version];
my @pinned = (
    ['relay/Cargo.toml', 'package version', $package_version],
    ['relay/Cargo.toml', 'natty dependency', qr/^(natty = \{[^}\n]*version = ")($semver)"/m],
    ['Cargo.lock', 'natty package', lock_entry('natty')],
    ['Cargo.lock', 'natty-relay package', lock_entry('natty-relay')],
    ['fuzz/Cargo.lock', 'natty package', lock_entry('natty')],
);
my @docs = ('README.md', 'relay/README.md', 'docs/index.html');

chdir File::Spec->catdir(dirname(__FILE__), '..') or die "cannot enter the repository root: $!\n";

sub read_file {
    my ($path) = @_;
    open my $fh, '<', $path or die "$path: $!\n";
    local $/;
    return <$fh>;
}

sub write_file {
    my ($path, $text) = @_;
    open my $fh, '>', $path or die "$path: $!\n";
    print {$fh} $text;
    close $fh or die "$path: $!\n";
}

sub version_at {
    my ($path, $what, $pattern) = @_;
    read_file($path) =~ $pattern or die "$path: no $what\n";
    return $2;
}

sub set_at {
    my ($path, $what, $pattern, $new) = @_;
    my $text = read_file($path);
    $text =~ s/$pattern/$1$new"/ or die "$path: no $what\n";
    write_file($path, $text);
}

sub versions_in_doc {
    my ($path) = @_;
    my $text = read_file($path);
    my @found;
    while ($text =~ /($svg)|($version_in_text)/g) {
        next if defined $1;
        my $line = 1 + (substr($text, 0, $-[2]) =~ tr/\n//);
        push @found, ["$path:$line", $2];
    }
    return @found;
}

sub set_doc {
    my ($path, $new) = @_;
    my $text = read_file($path);
    $text =~ s/($svg)|$version_in_text/defined $1 ? $1 : $new/ge;
    write_file($path, $text);
}

sub mismatches {
    my ($expected) = @_;
    my @found = (
        (map { ["$_->[0]: $_->[1]", version_at(@$_)] } @pinned),
        (map { versions_in_doc($_) } @docs),
    );
    return map { "$_->[0]: $_->[1]" } grep { $_->[1] ne $expected } @found;
}

my ($command, $new) = @ARGV;
$command //= '';
if ($command eq 'set') {
    defined $new && $new =~ /^$semver$/ or die $usage;
    set_at(@$_, $new) for $source, @pinned;
    set_doc($_, $new) for @docs;
} elsif ($command ne 'check') {
    die $usage;
}

my $expected = version_at(@$source);
my @wrong = mismatches($expected);
if (@wrong) {
    print STDERR "$_, expected $expected\n" for @wrong;
    die "To set every place to $expected, run: make version V=$expected\n";
}
print "version $expected in the manifests, lock files and docs\n";
