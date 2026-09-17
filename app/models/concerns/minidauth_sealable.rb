# frozen_string_literal: true

# Seal selected ActiveRecord attributes with minidauth before they reach Postgres, and open them again
# when a record is read, as the currently signed-in agent (Current.user), gated by a quorum-granted
# role. Include it in a model and declare the fields:
#
#   class Contact < ApplicationRecord
#     include MinidauthSealable
#     minidauth_seals :name, :phone_number
#   end
#
# Off unless MINIDAUTH_SEAL_URL is set, in which case every path is a no-op and the model behaves
# exactly like upstream. `drop:` lists derived plaintext copies to blank on write (for example a
# pre-rendered/processed field) so the sealed value is not shadowed by a plaintext duplicate.
require Rails.root.join('lib/minidauth/sidecar').to_s

module MinidauthSealable
  extend ActiveSupport::Concern

  included do
    class_attribute :minidauth_sealed_fields, instance_writer: false, default: []
    class_attribute :minidauth_dropped_fields, instance_writer: false, default: []

    before_save :minidauth_seal_on_write
    after_find :minidauth_open_on_read
  end

  class_methods do
    def minidauth_seals(*fields, drop: [])
      self.minidauth_sealed_fields = fields.map(&:to_s)
      self.minidauth_dropped_fields = Array(drop).map(&:to_s)
    end
  end

  private

  def minidauth_seal_on_write
    return unless Minidauth::Sidecar.enabled?

    leaves = minidauth_sealed_fields.select do |f|
      v = self[f]
      v.is_a?(String) && !v.empty? && !Minidauth::Sidecar.sealed?(v)
    end
    unless leaves.empty?
      sealed = Minidauth::Sidecar.seal(leaves.map { |f| self[f] })
      leaves.each_with_index { |f, i| self[f] = sealed[i] } # fails closed: a sidecar error raises here
    end

    # blank any derived plaintext copies so they cannot shadow the sealed value on read
    minidauth_dropped_fields.each { |f| self[f] = nil if self[f].present? }
  end

  def minidauth_open_on_read
    return unless Minidauth::Sidecar.enabled?

    reader = Current.respond_to?(:user) ? Current.user : nil
    token = reader ? Minidauth::Sidecar.reader_token(reader.id) : nil

    leaves = minidauth_sealed_fields.select { |f| Minidauth::Sidecar.sealed?(self[f]) }
    return if leaves.empty?

    opened = Minidauth::Sidecar.open(leaves.map { |f| self[f] }, token) # best effort; stays sealed on failure
    leaves.each_with_index { |f, i| self[f] = opened[i] }
    # the opened value is not a real change to persist
    clear_attribute_changes(leaves)
  end
end
